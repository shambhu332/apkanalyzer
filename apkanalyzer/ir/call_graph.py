"""
Inter-procedural call graph built from androguard Analysis.

Design decisions
----------------
- We use androguard's XRef mechanism rather than re-implementing call resolution
  because androguard resolves virtual dispatch at the Dalvik type level.
- We represent the CG as a networkx DiGraph so we can run standard graph
  algorithms (reachability, SCC, topological sort) without bespoke code.
- Framework filtering strategy:
    * Pure infrastructure (java.*, javax.*, sun.*, kotlin.*) is excluded as callers
      and their internal-only edges are dropped to keep the graph manageable.
    * Android/AndroidX framework methods ARE included as callers when they call
      app code — this captures lifecycle callbacks (Activity.onCreate → our code)
      and is critical for reachability analysis.
    * All callee nodes are always added so sink detection works (app → WebView.loadUrl).
"""

from __future__ import annotations

import logging
from typing import Iterator, Optional, Set

import networkx as nx

from apkanalyzer.ir.models import MethodDescriptor, CallEdge

logger = logging.getLogger(__name__)

# Pure infrastructure prefixes — always skip these as caller nodes.
# We do NOT include android.* / androidx.* here so lifecycle callbacks are captured.
_INFRA_PREFIXES = (
    "Ljava/",
    "Ljavax/",
    "Lsun/",
    "Ldalvik/",
)

# Kotlin stdlib / coroutines — generated boilerplate, not app logic.
# But Kotlin *user* code lives in user-package names, not under Lkotlin/ or Lkotlinx/.
_KOTLIN_INFRA_PREFIXES = (
    "Lkotlin/",
    "Lkotlinx/coroutines/",
)

# Android / AndroidX framework packages we STILL exclude as callers because
# they have enormous fan-out that would dominate the graph without value.
# We keep lifecycle-relevant ones by NOT including them here.
_FRAMEWORK_BULK_PREFIXES = (
    "Lcom/google/android/gms/internal/",
    "Lcom/google/android/material/internal/",
    "Landroidx/core/internal/",
    "Landroidx/collection/",
)

# Security-relevant sink classes — always included as callee nodes
# (this is already guaranteed by the build loop, but listed for documentation)
_SECURITY_SINK_PREFIXES = (
    "Landroid/webkit/WebView",
    "Landroid/database/sqlite/",
    "Landroid/content/ContentResolver",
    "Landroid/app/PendingIntent",
    "Ljava/lang/Runtime",
    "Ljava/lang/ProcessBuilder",
)


def _is_infra(class_name: str) -> bool:
    """True if this class is pure infrastructure that should never be a caller."""
    return (
        any(class_name.startswith(p) for p in _INFRA_PREFIXES)
        or any(class_name.startswith(p) for p in _KOTLIN_INFRA_PREFIXES)
        or any(class_name.startswith(p) for p in _FRAMEWORK_BULK_PREFIXES)
    )


def _is_android_framework(class_name: str) -> bool:
    """True if this is Android/AndroidX framework (but not pure java infra)."""
    return (
        class_name.startswith("Landroid/")
        or class_name.startswith("Landroidx/")
        or class_name.startswith("Lcom/google/android/")
    )


def _to_descriptor(method) -> Optional[MethodDescriptor]:
    """
    Convert an androguard MethodAnalysis, EncodedMethod, or ExternalMethod
    to our MethodDescriptor.
    """
    try:
        m = method.get_method() if hasattr(method, "get_method") else method
        return MethodDescriptor(
            class_name=m.get_class_name(),
            method_name=m.get_name(),
            descriptor=m.get_descriptor(),
        )
    except Exception:
        return None


class CallGraph:
    """
    Directed call graph: edge (A → B) means A calls B.

    Attributes
    ----------
    graph : nx.DiGraph
        Nodes are MethodDescriptor.full_name strings.
        Edge data: {'edge': CallEdge}
    class_hierarchy : dict[str, set[str]]
        parent_class → set of direct subclasses (Lcom/Foo; → {Lcom/Bar;, …}).
        Used for CHA virtual-dispatch resolution: when a call site
        targets `Parent;->m()` but only `Bar;->m()` exists in the app, we
        can still resolve through the hierarchy.
    interfaces : dict[str, set[str]]
        interface_class → set of implementing classes. Same role as
        class_hierarchy but for interface dispatch.
    """

    def __init__(self) -> None:
        self.graph: nx.DiGraph = nx.DiGraph()
        self._descriptors: dict[str, MethodDescriptor] = {}
        # Class hierarchy: parent → direct subclasses (and interface → impls).
        # Populated during build() from androguard's class metadata.
        self.class_hierarchy: dict[str, set[str]] = {}
        self.interfaces: dict[str, set[str]] = {}
        # Fast lookup: class_name → set of method (name, descriptor) tuples
        # actually defined on that class. Lets the taint engine ask "does
        # subclass X actually override method m?" in O(1).
        self._class_methods: dict[str, set[tuple[str, str]]] = {}

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def build(cls, dx) -> "CallGraph":
        """
        Build a call graph from an androguard Analysis object (dx).

        Parameters
        ----------
        dx : androguard.core.analysis.analysis.Analysis
        """
        cg = cls()

        # ── Class hierarchy (CHA) ──────────────────────────────────────
        # We populate this *first* so virtual-dispatch resolution works
        # even for callees that appear in the call graph before their
        # subclasses have been visited as edge targets.
        try:
            for class_analysis in dx.get_classes():
                try:
                    vm_cls = class_analysis.get_vm_class()
                    cls_name = vm_cls.get_name()
                    super_name = vm_cls.get_superclassname() or "Ljava/lang/Object;"
                    cg.class_hierarchy.setdefault(super_name, set()).add(cls_name)
                    # Interfaces — androguard exposes them as get_interfaces()
                    try:
                        for iface in vm_cls.get_interfaces() or []:
                            cg.interfaces.setdefault(iface, set()).add(cls_name)
                    except Exception:
                        pass
                    # Method table for this class — used by CHA to ask
                    # "does this subclass actually override the method?"
                    methods_on_class: set[tuple[str, str]] = set()
                    try:
                        for em in vm_cls.get_methods():
                            methods_on_class.add((em.get_name(), em.get_descriptor()))
                    except Exception:
                        pass
                    if methods_on_class:
                        cg._class_methods[cls_name] = methods_on_class
                except Exception:
                    continue
        except Exception as exc:
            logger.debug("Class hierarchy build failed: %s", exc)

        for method_analysis in dx.get_methods():
            caller_desc = _to_descriptor(method_analysis)
            if caller_desc is None:
                continue

            # Skip pure infrastructure (java.*, javax.*, kotlin stdlib) entirely.
            if _is_infra(caller_desc.class_name):
                continue

            try:
                xrefs = list(method_analysis.get_xref_to())
            except Exception:
                continue

            if _is_android_framework(caller_desc.class_name):
                # Android framework caller: only add edge if callee is app code.
                # This captures Activity.onCreate → our override, etc.
                for _, callee_analysis, offset in xrefs:
                    callee_desc = _to_descriptor(callee_analysis)
                    if callee_desc is None:
                        continue
                    if not _is_infra(callee_desc.class_name) and \
                            not _is_android_framework(callee_desc.class_name):
                        # Framework → app edge: include for lifecycle reachability
                        cg._add_node(caller_desc)
                        cg._add_node(callee_desc)
                        cg._add_edge(caller_desc, callee_desc, offset)
                continue

            # App code caller: add all edges (app → app AND app → framework sinks)
            cg._add_node(caller_desc)
            for _, callee_analysis, offset in xrefs:
                callee_desc = _to_descriptor(callee_analysis)
                if callee_desc is None:
                    continue
                # Always add callee node (needed for sink matching)
                cg._add_node(callee_desc)
                cg._add_edge(caller_desc, callee_desc, offset)

        logger.info(
            "Call graph built: %d nodes, %d edges",
            cg.graph.number_of_nodes(),
            cg.graph.number_of_edges(),
        )
        return cg

    def _add_node(self, desc: MethodDescriptor) -> None:
        key = desc.full_name
        if key not in self.graph:
            self.graph.add_node(key)
            self._descriptors[key] = desc

    def _add_edge(self, caller: MethodDescriptor, callee: MethodDescriptor,
                  offset: int) -> None:
        edge = CallEdge(caller=caller, callee=callee, call_site_offset=offset)
        self.graph.add_edge(caller.full_name, callee.full_name, edge=edge)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_descriptor(self, full_name: str) -> Optional[MethodDescriptor]:
        return self._descriptors.get(full_name)

    def callees(self, method: MethodDescriptor) -> list[MethodDescriptor]:
        """Direct callees of a method."""
        result = []
        for successor in self.graph.successors(method.full_name):
            desc = self._descriptors.get(successor)
            if desc:
                result.append(desc)
        return result

    def callers(self, method: MethodDescriptor) -> list[MethodDescriptor]:
        """Direct callers of a method."""
        result = []
        for predecessor in self.graph.predecessors(method.full_name):
            desc = self._descriptors.get(predecessor)
            if desc:
                result.append(desc)
        return result

    def reachable_from(self, root: MethodDescriptor) -> Set[str]:
        """All methods reachable (transitively) from root."""
        if root.full_name not in self.graph:
            return set()
        return nx.descendants(self.graph, root.full_name) | {root.full_name}

    def entry_points(self) -> list[MethodDescriptor]:
        """
        Methods with no callers within the app — likely entry points
        (Activity lifecycle, BroadcastReceiver, Service, etc.).
        """
        result = []
        for node in self.graph.nodes():
            if self.graph.in_degree(node) == 0:
                desc = self._descriptors.get(node)
                if desc:
                    result.append(desc)
        return result

    def path_between(
        self,
        source: MethodDescriptor,
        sink: MethodDescriptor,
    ) -> Optional[list[MethodDescriptor]]:
        """
        Shortest call path from source to sink, or None.
        Used by the taint engine to build the call chain in a TaintPath.
        """
        try:
            path = nx.shortest_path(
                self.graph, source.full_name, sink.full_name
            )
            return [self._descriptors[n] for n in path if n in self._descriptors]
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None

    def strongly_connected_components(self) -> list[list[MethodDescriptor]]:
        """Return SCCs — useful to detect mutual recursion."""
        sccs = []
        for scc in nx.strongly_connected_components(self.graph):
            group = [self._descriptors[n] for n in scc if n in self._descriptors]
            if len(group) > 1:
                sccs.append(group)
        return sccs

    def all_methods(self) -> Iterator[MethodDescriptor]:
        for key, desc in self._descriptors.items():
            yield desc

    # ------------------------------------------------------------------
    # CHA virtual dispatch
    # ------------------------------------------------------------------

    def cha_targets(
        self,
        class_name: str,
        method_name: str,
        descriptor: str,
        max_targets: int = 8,
    ) -> list[MethodDescriptor]:
        """
        Class Hierarchy Analysis: return descriptors for every concrete
        method that *could* be the runtime target of an `invoke-virtual`
        / `invoke-interface` against `class_name->method_name(descriptor)`.

        This is intentionally cheap and over-approximate — we walk
        subclasses (and interface implementations) and yield any of them
        that actually define the method. Callers should still bound the
        analysis cost: 8 alternative targets is enough to capture
        OkHttp `Interceptor.intercept`, Volley `Response.Listener`,
        and similar fan-out patterns without exploding on `Object` /
        `Iterable` / `Collection`.
        """
        # Avoid the universal-base-class explosion: any virtual call on
        # Ljava/lang/Object; is meaningless to expand.
        if class_name in ("Ljava/lang/Object;", "Ljava/lang/Iterable;",
                          "Ljava/util/Collection;", "Ljava/util/List;",
                          "Ljava/util/Map;", "Ljava/util/Set;"):
            return []

        # BFS over subclasses + interface impls. Visit each class once so
        # diamond hierarchies don't double-count.
        seen: set[str] = set()
        frontier: list[str] = [class_name]
        targets: list[MethodDescriptor] = []
        sig_key = (method_name, descriptor)

        while frontier and len(targets) < max_targets:
            cls = frontier.pop()
            if cls in seen:
                continue
            seen.add(cls)

            # Does this concrete class define the method?
            if sig_key in self._class_methods.get(cls, set()):
                full = f"{cls}->{method_name}{descriptor}"
                desc = self._descriptors.get(full)
                if desc is not None and desc.class_name != class_name:
                    targets.append(desc)
                    if len(targets) >= max_targets:
                        break

            # Enqueue subclasses + interface implementers
            for child in self.class_hierarchy.get(cls, ()):
                if child not in seen:
                    frontier.append(child)
            for impl in self.interfaces.get(cls, ()):
                if impl not in seen:
                    frontier.append(impl)

        return targets
