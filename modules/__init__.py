# recon_tool/modules/__init__.py
#
# Directory: recon_tool/modules/__init__.py
#
# Package marker for the `modules` sub-package.
#
# This file is intentionally minimal. It exists solely to
# make `modules` importable as a Python package. No symbols
# are exported from here; every module must be imported
# explicitly by its consumers so that the dependency graph
# remains obvious and auditable.
#
# Module inventory (import these directly, not via this file):
#
#   modules.http_helper   Centralised, rate-limited HTTP client
#   modules.tech_detect   Web-server / CMS / framework / cookie detection
#   modules.header_audit  HTTP security-header analysis
#   modules.dns_enum      DNS record enumeration (A, MX, NS, TXT, CNAME)
#   modules.whois_lookup  Domain registration data retrieval
#   modules.surface_map   Link / form / path / subdomain extraction
#   modules.js_analyzer   JavaScript static analysis
#   modules.report_gen    JSON and Markdown report generation
#
# Dependency rule:
#   Modules may import from modules.http_helper only.
#   Modules must never import from each other beyond that.
#   recon.py is the only file permitted to import from all modules.

"""
recon_tool.modules
==================
Sub-package containing every functional reconnaissance module.
See module docstrings for individual API documentation.
"""

__version__ = "1.0.0"
__all__: list = []  # Nothing is exported at package level
