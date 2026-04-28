"""
APKAnalyzer — advanced static analysis engine for Android APKs.

Pipeline:
  APK → Extraction → Decompilation → IR (CFG/DFG/CG) → Analysis → Scoring → Report
"""

__version__ = "1.0.0"

# Bump when detector rules / scoring / taint specs change. The scan cache uses
# this as part of its key so old cached reports are not returned after rules
# evolve. Bump on any change that would alter findings for the same APK.
RULES_VERSION = "2"

# Default max call-graph depth for inter-procedural taint propagation.
# Used by both the CLI and the web app so they don't drift apart silently.
# Above ~10 the analysis time grows quadratically with little marginal recall;
# below 6 we miss common helper indirection. 8 is the empirical sweet spot.
DEFAULT_TAINT_DEPTH = 8
