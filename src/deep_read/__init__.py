"""
Deep Read — given a subdomain, produce a ranked list of testable
hypotheses for manual bug bounty investigation.

Flow: fetch homepage + JS bundles → parse endpoints → probe specs
→ Claude Opus reasoning pass → kill-list gate → markdown report.
"""
from .cli import run_deep_read  # noqa: F401
