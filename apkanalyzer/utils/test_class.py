"""
Single source of truth for "is this a test/build/debug class?".

Why this module exists
----------------------
Three callers — the taint engine, the YAML rule engine, and the pipeline
orchestrator — all need to skip test/mock/debug code. Keeping three copies
of the predicate (with three different definitions of "test") meant a
class would get scanned by detector A but skipped by detector B, producing
inconsistent reports. We promote the predicate here and route every other
caller through it.

Naming rules
------------
We want to skip `Lcom/foo/LoginTest;`, `Lcom/foo/SomeMock;`, `Lcom/foo/test/Foo;`
without false-positive matches like `Lcom/foo/Latest;` (substring "test"
inside `Latest`) or `Lcom/foo/Stubble;`. Java/Kotlin convention says class
identifiers start with uppercase, so we only match `Test`/`Mock`/`Fake`/`Stub`
when they appear case-sensitive at the start or end of the basename
(the segment after the last `/`).
"""

from __future__ import annotations

import re

# Path-segment matches: classes physically living in a test source set
# (`/test/`, `/androidTest/`) or under a generated framework namespace.
_TEST_PATH_RE = re.compile(r'/(?:test|androidTest|robolectric|espresso)/')

# Synthesised classes — never user code, always safe to skip.
_BUILDCONFIG_RE = re.compile(r'/BuildConfig(?:\$|;|$)')
_R_RES_RE = re.compile(r'/R\$')

# Framework markers anywhere in the classpath.
_FRAMEWORK_RE = re.compile(
    r'/(?:JUnit|Junit|junit|Espresso|espresso|Robolectric|robolectric|'
    r'Mockito|mockito|PowerMock|powermock|Truth|truth)\w*[/$;]'
)

# Basename-level markers. Match when the segment after the last `/` (or `$`
# for inner classes) starts with `Test`/`Mock`/`Fake`/`Stub` followed by an
# uppercase letter or digit (camelCase boundary), or ends with one of those
# markers preceded by a lowercase letter / digit (camelCase end).
#
# This rejects `Latest;` (Test preceded by `a`, not capitalised), `Stubble;`
# (Stub followed by `b`, not capitalised), `Debugger;` (Debug followed by
# `g`), and `Faker;` (Fake followed by `r`).
_BASENAME_START_RE = re.compile(
    r'(?:/|\$)(?:Test|Mock|Fake|Stub|Debug)(?:[A-Z0-9]\w*)?(?:\$|;|$)'
)
_BASENAME_END_RE = re.compile(
    r'(?:/|\$)\w*?[a-z0-9](?:Test|Mock|Fake|Stub|Debug)(?:s)?(?:\$|;|$)'
)


def is_test_class(class_name: str) -> bool:
    """
    True for classes the analysis should skip:
      • Generated (BuildConfig, R$drawable, …)
      • Test sources (LoginTest, MockUserDao, /test/, JUnit*, Robolectric*)
      • Debug-flavoured classes the developer never intended to ship

    `class_name` should be the raw Smali descriptor or path
    (e.g., `Lcom/foo/bar/SomeTest;` or `com/foo/bar/SomeTest`).
    """
    return bool(
        _TEST_PATH_RE.search(class_name)
        or _BUILDCONFIG_RE.search(class_name)
        or _R_RES_RE.search(class_name)
        or _FRAMEWORK_RE.search(class_name)
        or _BASENAME_START_RE.search(class_name)
        or _BASENAME_END_RE.search(class_name)
    )
