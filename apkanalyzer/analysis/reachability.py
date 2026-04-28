"""
Reachability analysis — computes the set of methods reachable from
well-known Android entry points.

Entry points now cover the full modern Android framework:
  - Activity/Fragment lifecycle (including Jetpack)
  - BroadcastReceiver.onReceive (static + dynamic)
  - Service / IntentService / JobIntentService
  - WorkManager (ListenableWorker.doWork, Worker.doWork, CoroutineWorker)
  - JobScheduler (JobService.onStartJob/onStopJob)
  - AlarmManager targets (BroadcastReceiver.onReceive)
  - Handler.handleMessage / Runnable.run
  - ContentProvider CRUD methods
  - Application.onCreate / attachBaseContext
  - View callbacks (onClick, onLongClick, onTouch, onKey)
  - Permission callbacks (onRequestPermissionsResult)
  - Activity result callbacks (onActivityResult, registerForActivityResult)
  - Firebase / Push messaging callbacks
  - Static initializers and constructors
"""

from __future__ import annotations

import logging
from typing import Set

from apkanalyzer.ir.call_graph import CallGraph
from apkanalyzer.ir.models import MethodDescriptor

logger = logging.getLogger(__name__)

# ── Android lifecycle entry-point method names ─────────────────────────────
_LIFECYCLE_METHODS = {
    # Activity
    "onCreate", "onStart", "onResume", "onPause", "onStop", "onDestroy",
    "onRestart", "onSaveInstanceState", "onRestoreInstanceState",
    "onActivityResult", "onRequestPermissionsResult",
    "onNewIntent", "onBackPressed", "onOptionsItemSelected",
    "onContextItemSelected", "onCreateOptionsMenu", "onPrepareOptionsMenu",
    "onWindowFocusChanged", "onConfigurationChanged",
    # Fragment
    "onCreateView", "onViewCreated", "onActivityCreated",
    "onAttach", "onDetach", "onDestroyView", "onHiddenChanged",
    "onViewStateRestored",
    # BroadcastReceiver
    "onReceive",
    # Service
    "onStartCommand", "onBind", "onUnbind", "onRebind", "onTaskRemoved",
    "onHandleIntent", "onHandleWork",
    # JobService (JobScheduler)
    "onStartJob", "onStopJob",
    # WorkManager
    "doWork", "startWork", "getForegroundInfoAsync",
    # ContentProvider
    "query", "insert", "update", "delete", "getType", "call",
    "openFile", "openAssetFile", "applyBatch",
    # Application
    "attachBaseContext",
    # View / UI callbacks
    "onClick", "onLongClick", "onTouch", "onKey", "onFocusChange",
    "onCheckedChanged", "onItemClick", "onItemLongClick", "onItemSelected",
    "onTextChanged", "afterTextChanged", "beforeTextChanged",
    # RecyclerView
    "onBindViewHolder", "onCreateViewHolder",
    # Handler / Runnable
    "handleMessage", "run", "call",
    # Coroutine / RxJava
    "subscribe", "onNext", "onError", "onComplete",
    # Firebase
    "onMessageReceived", "onNewToken", "onNotificationReceived",
    # Static init + constructors
    "<init>", "<clinit>",
}

# ── Base classes that identify exported Android components ─────────────────
_COMPONENT_BASE_CLASSES = (
    # Activity / AppCompatActivity / FragmentActivity
    "Landroid/app/Activity;",
    "Landroidx/appcompat/app/AppCompatActivity;",
    "Landroidx/fragment/app/FragmentActivity;",
    "Landroid/app/ListActivity;",
    "Landroid/preference/PreferenceActivity;",
    # Fragment
    "Landroid/app/Fragment;",
    "Landroidx/fragment/app/Fragment;",
    "Landroid/preference/PreferenceFragment;",
    "Landroidx/preference/PreferenceFragmentCompat;",
    # Service
    "Landroid/app/Service;",
    "Landroid/app/IntentService;",
    "Landroidx/core/app/JobIntentService;",
    # BroadcastReceiver
    "Landroid/content/BroadcastReceiver;",
    # ContentProvider
    "Landroid/content/ContentProvider;",
    # Application
    "Landroid/app/Application;",
    "Landroidx/multidex/MultiDexApplication;",
    # View / ViewGroup
    "Landroid/view/View;",
    "Landroid/view/ViewGroup;",
    # WorkManager
    "Landroidx/work/Worker;",
    "Landroidx/work/ListenableWorker;",
    "Landroidx/work/CoroutineWorker;",
    "Landroidx/work/RxWorker;",
    # JobService
    "Landroid/app/job/JobService;",
    # Firebase
    "Lcom/google/firebase/messaging/FirebaseMessagingService;",
    "Lcom/google/firebase/iid/FirebaseInstanceIdService;",
    # RecyclerView
    "Landroidx/recyclerview/widget/RecyclerView$Adapter;",
    "Landroidx/recyclerview/widget/RecyclerView$ViewHolder;",
)

# ── Interface-based entry points (implement these → lifecycle methods run) ─
_CALLBACK_INTERFACES = (
    "Landroid/view/View$OnClickListener;",
    "Landroid/view/View$OnLongClickListener;",
    "Landroid/view/View$OnTouchListener;",
    "Landroid/widget/CompoundButton$OnCheckedChangeListener;",
    "Landroid/widget/AdapterView$OnItemClickListener;",
    "Landroid/widget/AdapterView$OnItemSelectedListener;",
    "Landroid/text/TextWatcher;",
    "Landroid/os/Handler$Callback;",
    "Ljava/lang/Runnable;",
    "Ljava/util/concurrent/Callable;",
    "Lio/reactivex/functions/Consumer;",
    "Lio/reactivex/functions/Action;",
)


def compute_reachable_methods(
    call_graph: CallGraph,
    dx,
) -> Set[str]:
    """
    Return the set of full method names reachable from Android entry points.
    """
    roots = _find_entry_points(call_graph, dx)
    logger.info("Found %d entry-point methods", len(roots))

    reachable: Set[str] = set()
    for root in roots:
        reachable |= call_graph.reachable_from(root)

    reachable |= {r.full_name for r in roots}

    logger.info("Reachable method set: %d methods", len(reachable))
    return reachable


def _find_entry_points(
    call_graph: CallGraph,
    dx,
) -> list[MethodDescriptor]:
    """
    Identify Android entry-point methods using three strategies:

    1. Class hierarchy: if a class extends/implements a known Android
       component base class or callback interface, its lifecycle methods
       are entry points.
    2. Call-graph roots: methods with in-degree 0 (OS calls them directly).
    3. Interface implementations: classes implementing known callback
       interfaces expose their methods as entry points.
    """
    entry_points: list[MethodDescriptor] = []

    for method_desc in call_graph.all_methods():
        if method_desc.method_name not in _LIFECYCLE_METHODS:
            continue

        class_name = method_desc.class_name

        if _is_component_subclass(class_name, dx):
            entry_points.append(method_desc)
            continue

        if _implements_callback_interface(class_name, dx):
            entry_points.append(method_desc)
            continue

    # Strategy 2: CG roots that match lifecycle names
    for desc in call_graph.entry_points():
        if desc.method_name in _LIFECYCLE_METHODS:
            entry_points.append(desc)

    # Deduplicate
    seen: set[str] = set()
    unique: list[MethodDescriptor] = []
    for d in entry_points:
        if d.full_name not in seen:
            seen.add(d.full_name)
            unique.append(d)

    return unique


def _is_component_subclass(class_name: str, dx) -> bool:
    """Check whether class_name is a subclass of a known Android component."""
    try:
        class_analysis = dx.get_class_analysis(class_name)
        if class_analysis is None:
            return False

        visited: set[str] = set()
        queue = [class_name]
        while queue:
            current = queue.pop()
            if current in visited:
                continue
            visited.add(current)

            if current in _COMPONENT_BASE_CLASSES:
                return True

            ca = dx.get_class_analysis(current)
            if ca is None:
                continue

            try:
                vm_class = ca.get_vm_class()
                superclass = vm_class.get_superclassname()
                if superclass and superclass not in visited:
                    queue.append(superclass)
                # Also check implemented interfaces
                for iface in (vm_class.get_interfaces() or []):
                    if iface and iface not in visited:
                        queue.append(iface)
            except Exception:
                pass
    except Exception:
        pass
    return False


def _implements_callback_interface(class_name: str, dx) -> bool:
    """Check whether class_name implements a known Android callback interface."""
    try:
        ca = dx.get_class_analysis(class_name)
        if ca is None:
            return False
        vm = ca.get_vm_class()
        for iface in (vm.get_interfaces() or []):
            if iface in _CALLBACK_INTERFACES:
                return True
    except Exception:
        pass
    return False
