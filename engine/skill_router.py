"""
Chronos-DFIR Skill Router — Central registry mapping skills to real code.
Created: 2026-03-08

Each skill is categorized by its integration status:
  - ACTIVE:      Has production code running in engine/ or app.py
  - WIRED:       Has .py code in skills/ but not yet called from app.py
  - PROMPT_ONLY: Has SKILL.md (AI system prompt) but no executable code
  - FRONTEND:    Implemented in static/js/ (browser-side)
  - RULES:       Implemented via Sigma YAML or YARA rules in rules/

This registry enables:
  1. Quick audit of what's real vs documentation
  2. Incremental activation of prompt-only skills
  3. Dependency tracking for multi-agent coordination
"""

import logging
from typing import Dict, Any

logger = logging.getLogger("Chronos-DFIR")

# ── Status Constants ────────────────────────────────────────────────────────

ACTIVE = "active"          # Production code running
WIRED = "wired"            # Code exists but not integrated into app.py
PROMPT_ONLY = "prompt_only" # SKILL.md only — AI consultation prompt
FRONTEND = "frontend"      # Implemented in JS/CSS/HTML
RULES = "rules"            # Implemented via Sigma/YARA rules

# ── Skill Registry ─────────────────────────────────────────────────────────

SKILL_REGISTRY: Dict[str, Dict[str, Any]] = {

    # ═══════════════════════════════════════════════════════════════════════
    # ACTIVE — Production code in engine/ or app.py
    # ═══════════════════════════════════════════════════════════════════════

    "chronos_sigma_engine": {
        "status": ACTIVE,
        "skill_number": 46,
        "module": "engine.sigma_engine",
        "description": "EVTX Fast-Hunter — YAML-to-Polars Sigma rule compiler",
        "implements": ["load_sigma_rules()", "match_sigma_rules()"],
        "used_by": ["app.py:forensic_report", "engine/forensic.py:generate_export_payloads"],
    },
    "chronos_format_master": {
        "status": ACTIVE,
        "skill_number": 23,
        "module": "engine.ingestor",
        "description": "Parsing Architect — Multi-format ingestion engine",
        "implements": ["ingest_file()", "_read_whitespace_csv()", "Excel/JSON/SQLite/Plist parsing"],
        "used_by": ["app.py:upload"],
    },
    "chronos_universal_ingestion": {
        "status": ACTIVE,
        "skill_number": 52,
        "module": "engine.ingestor",
        "description": "Multi-Format Gatekeeper — Fingerprinting & normalization",
        "implements": ["Column fingerprinting", "Format detection", "Streaming ingestion"],
        "used_by": ["app.py:upload"],
    },
    "chronos_streaming_architect": {
        "status": ACTIVE,
        "skill_number": None,
        "module": "engine.ingestor",
        "description": "Streaming pipeline — scan_csv + sink_csv for large files",
        "implements": ["Polars LazyFrame streaming", "Chunked processing"],
        "used_by": ["app.py:upload", "app.py:export_filtered"],
    },
    "chronos_timeline_choreographer": {
        "status": ACTIVE,
        "skill_number": 26,
        "module": "engine.forensic",
        "description": "Multi-Source Fusion — Timeline analysis & time hierarchy",
        "implements": ["sub_analyze_timeline()", "TIME_HIERARCHY", "EPS calculation"],
        "used_by": ["app.py:forensic_report"],
    },
    "chronos_triage_scoring": {
        "status": ACTIVE,
        "skill_number": None,
        "module": "engine.forensic",
        "description": "Risk scoring engine — Smart Risk M4 algorithm",
        "implements": ["calculate_smart_risk_m4()", "Risk Level assignment"],
        "used_by": ["app.py:forensic_report", "engine/forensic.py:generate_export_payloads"],
    },
    "chronos_visual_report_architect": {
        "status": ACTIVE,
        "skill_number": 51,
        "module": "app.py",
        "description": "HTML Exporter — Standalone forensic report generator",
        "implements": ["/api/export/html endpoint", "static_report.html rendering"],
        "used_by": ["app.py:export_html"],
    },
    "chronos_extract_actionable_intel": {
        "status": ACTIVE,
        "skill_number": None,
        "module": "engine.forensic",
        "description": "IoC Extractor — Extracts IPs, users, hosts, processes",
        "implements": ["sub_analyze_context()", "sub_analyze_hunting()"],
        "used_by": ["app.py:forensic_report"],
    },
    "chronos_detection_engineer": {
        "status": ACTIVE,
        "skill_number": None,
        "module": "engine.sigma_engine",
        "description": "Detection engineering — Sigma + YARA rule authoring",
        "implements": ["Sigma YAML compilation", "YARA rule matching"],
        "used_by": ["engine/sigma_engine.py"],
    },
    "chronos_unified_dfir_report": {
        "status": ACTIVE,
        "skill_number": None,
        "module": "engine.forensic",
        "description": "Unified Report Generator — Parallel sub-analysis fusion",
        "implements": ["generate_export_payloads()", "asyncio.gather orchestration"],
        "used_by": ["app.py:forensic_report", "app.py:export_filtered"],
    },

    # ═══════════════════════════════════════════════════════════════════════
    # RULES — Implemented via Sigma YAML or YARA in rules/
    # ═══════════════════════════════════════════════════════════════════════

    "chronos_lolbins_hunter": {
        "status": RULES,
        "skill_number": None,
        "module": "rules/sigma/ + rules/yara/lolbin/",
        "description": "LOLBins detection — certutil, regsvr32, mshta, rundll32, bitsadmin",
        "implements": ["6 YARA rules", "Sigma rules for T1218.*"],
        "rule_count": 6,
    },
    "chronos_persistence_analyst": {
        "status": RULES,
        "skill_number": None,
        "module": "rules/sigma/ta0003_persistence/",
        "description": "Persistence detection — Registry Run Keys, LaunchD, Services",
        "implements": ["T1543.003", "T1543.004", "T1547.001", "T1053.005", "T1136.001"],
        "rule_count": 5,
    },
    "chronos_ransomware_commander": {
        "status": RULES,
        "skill_number": 32,
        "module": "rules/yara/ransomware/",
        "description": "RaaS Expert — LockBit, Conti, QILIN/Agenda detection",
        "implements": ["LockBit patterns", "Conti IOCs", "Shadow copy wipe", "QILIN 5 rules"],
        "rule_count": 10,
    },
    "chronos_trojan_c2_analyst": {
        "status": RULES,
        "skill_number": 37,
        "module": "rules/yara/infostealers/ + rules/yara/c2_frameworks/",
        "description": "InfoStealers & RATs — Browser theft, RedLine, CobaltStrike, Sliver",
        "implements": ["Browser credential theft", "C2 beacon detection", "DNS tunneling"],
        "rule_count": 11,
    },
    "chronos_owasp_investigator": {
        "status": RULES,
        "skill_number": 47,
        "module": "rules/sigma/owasp/",
        "description": "Web Forensics — SQLi, XSS, SSRF, Brute Force detection",
        "implements": ["A03 SQLi/XSS", "A07 Brute Force", "A10 SSRF"],
        "rule_count": 4,
    },

    # ═══════════════════════════════════════════════════════════════════════
    # FRONTEND — Implemented in static/js/
    # ═══════════════════════════════════════════════════════════════════════

    "chronos_filter_architect": {
        "status": FRONTEND,
        "skill_number": None,
        "module": "static/js/grid.js",
        "description": "Tabulator Surgeon — Column filtering, virtual rendering",
        "implements": ["Column filters", "Hide empty columns", "Row filtering"],
    },
    "chronos_tabulator_master": {
        "status": FRONTEND,
        "skill_number": None,
        "module": "static/js/grid.js",
        "description": "Grid management — Tabulator vDOM, pagination, sorting",
        "implements": ["Virtual DOM rendering", "Remote pagination", "Column management"],
    },
    "chronos_ui_architect": {
        "status": FRONTEND,
        "skill_number": None,
        "module": "static/js/main.js + templates/index.html",
        "description": "UI/UX architecture — Drag-drop, modals, responsive layout",
        "implements": ["Upload zone", "Export panel", "Forensic modal", "State management"],
    },
    "chronos_visual_storyteller": {
        "status": FRONTEND,
        "skill_number": 42,
        "module": "static/js/charts.js",
        "description": "Data Visualization — Chart.js histograms, risk-colored bars",
        "implements": ["ChartManager", "Histogram bucketing", "Trend detection"],
    },
    "chronos_frontend_paramedic": {
        "status": FRONTEND,
        "skill_number": None,
        "module": "static/js/",
        "description": "Frontend debugging — Cache issues, state sync, DOM fixes",
        "implements": ["Diagnostic procedures for JS bugs"],
    },

    # ═══════════════════════════════════════════════════════════════════════
    # WIRED — Has .py code but NOT integrated into app.py
    # ═══════════════════════════════════════════════════════════════════════

    "chronos_timeseries_builder": {
        "status": ACTIVE,
        "skill_number": None,
        "module": ".agents/skills/chronos_timeseries_builder/builder.py",
        "description": "Time-series construction — /api/timeseries/{filename} endpoint",
        "implements": ["build_chronos_timeseries()"],
        "used_by": ["app.py:get_timeseries"],
    },
    "chronos_telemetry_parser": {
        "status": PROMPT_ONLY,
        "skill_number": None,
        "description": "DEPRECATED — Overlaps 70% with active sub_analyze_context(). Use engine/forensic.py instead.",
        "priority": "low",
        "could_implement": "Already superseded by sub_analyze_context + sub_analyze_hunting",
    },
    "chronos_forensic_doc_processor": {
        "status": ACTIVE,
        "skill_number": None,
        "module": ".agents/skills/chronos_forensic_doc_processor/forensic_doc_processor.py",
        "description": "PDF IOC Extractor & XLSX Integrity — Adapted from ComposioHQ",
        "implements": ["extract_pdf_text()", "extract_iocs_from_pdf_text()", "check_xlsx_integrity()"],
        "used_by": ["app.py:/api/document/extract_iocs", "app.py:/api/document/check_xlsx"],
    },
    "chronos_yara_scanner": {
        "status": ACTIVE,
        "skill_number": None,
        "module": "app.py + rules/yara/",
        "description": "YARA Runtime Scanner — 36 rules across 7 categories, on-demand file scanning",
        "implements": ["_load_yara_rules()", "/api/yara_scan/{filename}"],
        "used_by": ["app.py:yara_scan"],
    },

    # ═══════════════════════════════════════════════════════════════════════
    # PROMPT_ONLY — SKILL.md consultation prompts (no executable code)
    # ═══════════════════════════════════════════════════════════════════════

    # -- DFIR & Investigation Skills --
    "chronos_correlation_architect": {
        "status": ACTIVE, "skill_number": 15,
        "module": "engine.forensic",
        "description": "Cross-Tool Pattern Expert — Correlates events across data sources",
        "implements": ["correlate_cross_source()"],
        "used_by": ["app.py:forensic_report", "engine/forensic.py:generate_export_payloads"],
    },
    "chronos_blackhat_apt": {
        "status": PROMPT_ONLY, "skill_number": 20,
        "description": "APT Black Hat Mindset — Adversary thinking for threat modeling",
        "priority": "low",
        "could_implement": "AI prompt skill, no backend code needed",
    },
    "chronos_malware_analyst": {
        "status": PROMPT_ONLY, "skill_number": 21,
        "description": "Reverse Engineer — Malware analysis methodology",
        "priority": "low",
        "could_implement": "AI prompt skill, no backend code needed",
    },
    "chronos_red_teamer": {
        "status": PROMPT_ONLY, "skill_number": 22,
        "description": "Adversary Emulation — Red team attack simulation",
        "priority": "low",
        "could_implement": "AI prompt skill, no backend code needed",
    },
    "chronos_case_architect": {
        "status": PROMPT_ONLY, "skill_number": 24,
        "description": "DB & Case Management — Evidence database design",
        "priority": "medium",
        "could_implement": "SQLite case DB in engine/",
    },
    "chronos_chain_of_custody": {
        "status": ACTIVE, "skill_number": 25,
        "module": "app.py",
        "description": "Evidentiary Integrity — SHA256 hash computed during streaming upload",
        "implements": ["SHA256 hashing on upload", "chain_of_custody in API response"],
        "used_by": ["app.py:process_file"],
    },
    "chronos_mcp_integration": {
        "status": PROMPT_ONLY, "skill_number": 27,
        "description": "MCP/SOAR Integrator — External tool integration",
        "priority": "high",
        "could_implement": "MCP server endpoints for Claude Desktop integration (Etapa 3)",
    },
    "chronos_cti_analyst": {
        "status": ACTIVE, "skill_number": 28,
        "module": "engine.enrichment",
        "description": "Cyber Threat Intelligence — IOC enrichment via AbuseIPDB, VirusTotal, IP-API, URLhaus, URLScan, HIBP",
        "implements": ["enrich_all_iocs()", "enrich_single_ioc()", "deduplicate_iocs()"],
        "used_by": ["app.py:forensic_report", "app.py:enrichment_lookup"],
    },
    "chronos_log_management": {
        "status": PROMPT_ONLY, "skill_number": 29,
        "description": "Data Lake/SIEM — Log aggregation architecture",
        "priority": "low",
        "could_implement": "AI prompt skill for architecture decisions",
    },
    "chronos_db_architect": {
        "status": PROMPT_ONLY, "skill_number": 30,
        "description": "DBA & Data Modeler — Database optimization",
        "priority": "low",
        "could_implement": "AI prompt skill, no backend code needed",
    },
    "chronos_devops_sre": {
        "status": PROMPT_ONLY, "skill_number": 31,
        "description": "Infrastructure/DevOps — Deployment & monitoring",
        "priority": "low",
        "could_implement": "AI prompt skill for ops decisions",
    },
    "chronos_raas_architect": {
        "status": PROMPT_ONLY, "skill_number": 33,
        "description": "RaaS Core Developer — Ransomware architecture analysis",
        "priority": "low",
        "could_implement": "AI prompt skill, no backend code needed",
    },
    "chronos_dfir_sage": {
        "status": PROMPT_ONLY, "skill_number": 34,
        "description": "DFIR Veteran/Crisis Control — Senior advisor",
        "priority": "low",
        "could_implement": "AI prompt skill, no backend code needed",
    },
    "chronos_noc_expert": {
        "status": PROMPT_ONLY, "skill_number": 35,
        "description": "Network Operations — Network forensics methodology",
        "priority": "low",
        "could_implement": "AI prompt skill, no backend code needed",
    },
    "chronos_phishing_bec": {
        "status": PROMPT_ONLY, "skill_number": 36,
        "description": "Email/BEC Expert — Phishing investigation",
        "priority": "low",
        "could_implement": "AI prompt skill, email header parser could be added",
    },
    "chronos_roundtable_moderator": {
        "status": PROMPT_ONLY, "skill_number": 38,
        "description": "Incident Commander — Multi-agent coordination",
        "priority": "medium",
        "could_implement": "Session orchestration in .agents/",
    },
    "chronos_legal_counsel": {
        "status": PROMPT_ONLY, "skill_number": 39,
        "description": "Cybersecurity Counsel — Legal compliance advice",
        "priority": "low",
        "could_implement": "AI prompt skill, no backend code needed",
    },
    "chronos_ai_architect": {
        "status": PROMPT_ONLY, "skill_number": 40,
        "description": "AI/LLM Integrator — LLM pipeline architecture",
        "priority": "medium",
        "could_implement": "AI-powered analysis endpoint",
    },
    "chronos_tech_writer": {
        "status": PROMPT_ONLY, "skill_number": 41,
        "description": "Release Manager — Documentation & changelog",
        "priority": "low",
        "could_implement": "AI prompt skill, no backend code needed",
    },
    "chronos_devsecops_auditor": {
        "status": PROMPT_ONLY, "skill_number": 43,
        "description": "AppSec Engineer — Code security review",
        "priority": "low",
        "could_implement": "AI prompt skill for code review",
    },
    "chronos_mitre_strategist": {
        "status": ACTIVE, "skill_number": 44,
        "module": "engine.forensic",
        "description": "MITRE ATT&CK Mapping — Kill chain view from sigma hits",
        "implements": ["map_mitre_from_sigma()"],
        "used_by": ["app.py:forensic_report", "engine/forensic.py:generate_export_payloads"],
    },
    "chronos_execution_forensics": {
        "status": ACTIVE, "skill_number": 45,
        "module": "engine.forensic",
        "description": "Shimcache/Amcache/Prefetch/SRUM — Execution artifact detection",
        "implements": ["detect_execution_artifacts()"],
        "used_by": ["app.py:forensic_report", "engine/forensic.py:generate_export_payloads"],
    },
    "chronos_forensic_repository": {
        "status": PROMPT_ONLY, "skill_number": 48,
        "description": "Dataset & Test Builder — Forensic test data generation",
        "priority": "medium",
        "could_implement": "Test fixture generator in tests/",
    },
    "chronos_waf_decoder": {
        "status": ACTIVE, "skill_number": 49,
        "module": "engine.forensic",
        "description": "WAF Telemetry Normalizer — Vendor-agnostic WAF log decoder with double-encoding support",
        "implements": ["generate_waf_threat_profiles()", "_decode_waf_payload()"],
        "used_by": ["engine/forensic.py:sub_analyze_context"],
    },
    "chronos_session_grouper": {
        "status": ACTIVE, "skill_number": 50,
        "module": "engine.forensic",
        "description": "Threat Profiler — Session clustering & attacker profiling",
        "implements": ["group_sessions()"],
        "used_by": ["app.py:forensic_report", "engine/forensic.py:generate_export_payloads"],
    },

    # -- Business & Communication Skills --
    "chronos_commercial_consultant": {
        "status": PROMPT_ONLY, "skill_number": 16,
        "description": "DFIR Sales B2B — Commercial strategy",
        "priority": "low",
        "could_implement": "AI prompt skill, no backend code needed",
    },
    "chronos_crisis_pm": {
        "status": PROMPT_ONLY, "skill_number": 17,
        "description": "IR Project Manager — Incident response management",
        "priority": "low",
        "could_implement": "AI prompt skill, no backend code needed",
    },
    "chronos_account_operations_manager": {
        "status": PROMPT_ONLY, "skill_number": 18,
        "description": "AOM/Service Delivery — Account management",
        "priority": "low",
        "could_implement": "AI prompt skill, no backend code needed",
    },
    "chronos_tech_evangelist": {
        "status": PROMPT_ONLY, "skill_number": 19,
        "description": "Tech Storyteller/PR — Technical communication",
        "priority": "low",
        "could_implement": "AI prompt skill, no backend code needed",
    },
    "chronos_storytelling_expert": {
        "status": PROMPT_ONLY, "skill_number": None,
        "description": "Narrative construction for forensic reports",
        "priority": "low",
        "could_implement": "AI prompt skill, no backend code needed",
    },

    # -- Architecture & Ops Skills (pre-existing) --
    "chronos_master_auditor": {
        "status": PROMPT_ONLY, "skill_number": None,
        "description": "Master auditor — Code quality & architecture review",
        "priority": "low",
        "could_implement": "AI prompt skill, no backend code needed",
    },
    "chronos_executive_auditor": {
        "status": PROMPT_ONLY, "skill_number": None,
        "description": "Executive-level audit summaries",
        "priority": "low",
        "could_implement": "AI prompt skill, no backend code needed",
    },
    "chronos_soc_auditor": {
        "status": PROMPT_ONLY, "skill_number": None,
        "description": "SOC operations auditing",
        "priority": "low",
        "could_implement": "AI prompt skill, no backend code needed",
    },
    "chronos_network_auditor": {
        "status": PROMPT_ONLY, "skill_number": None,
        "description": "Network infrastructure auditing",
        "priority": "low",
        "could_implement": "AI prompt skill, no backend code needed",
    },
    "chronos_advisor_orchestration": {
        "status": PROMPT_ONLY, "skill_number": None,
        "description": "Multi-agent orchestration advisor",
        "priority": "medium",
        "could_implement": "Agent coordination protocol",
    },
    "chronos_event_bus": {
        "status": PROMPT_ONLY, "skill_number": None,
        "description": "Event-driven architecture design",
        "priority": "low",
        "could_implement": "AI prompt skill, no backend code needed",
    },
    "chronos_telemetry_architect": {
        "status": PROMPT_ONLY, "skill_number": None,
        "description": "Telemetry pipeline architecture",
        "priority": "low",
        "could_implement": "AI prompt skill, no backend code needed",
    },
    "chronos_telemetry_translator": {
        "status": PROMPT_ONLY, "skill_number": None,
        "description": "Cross-vendor telemetry normalization",
        "priority": "medium",
        "could_implement": "Field mapping in engine/ingestor.py",
    },
    "chronos_timeline_curator": {
        "status": PROMPT_ONLY, "skill_number": None,
        "description": "Timeline data curation & cleaning",
        "priority": "low",
        "could_implement": "Already partially in engine/forensic.py",
    },

    # -- External / Utility Skills (from ComposioHQ) --
    "webapp-testing": {
        "status": PROMPT_ONLY, "skill_number": None,
        "description": "Playwright testing toolkit with uvicorn lifecycle",
        "priority": "medium",
        "could_implement": "E2E test framework for Chronos UI",
    },
    "mcp-builder": {
        "status": PROMPT_ONLY, "skill_number": None,
        "description": "MCP server development guide",
        "priority": "medium",
        "could_implement": "Build Chronos MCP server for agent integration",
    },
    "changelog-generator": {
        "status": PROMPT_ONLY, "skill_number": None,
        "description": "Auto-generates release notes from git history",
        "priority": "low",
        "could_implement": "AI prompt skill, no backend code needed",
    },
    "skill-creator": {
        "status": PROMPT_ONLY, "skill_number": None,
        "description": "Meta-skill for creating new skills",
        "priority": "low",
        "could_implement": "AI prompt skill, no backend code needed",
    },
    "theme-factory": {
        "status": PROMPT_ONLY, "skill_number": None,
        "description": "Professional theme palettes & fonts",
        "priority": "low",
        "could_implement": "CSS theme variables for Chronos UI",
    },
    "document-skills-pdf": {
        "status": PROMPT_ONLY, "skill_number": None,
        "description": "PDF extraction, creation, OCR",
        "priority": "medium",
        "could_implement": "PDF report generation for forensic exports",
    },
    "document-skills-xlsx": {
        "status": WIRED, "skill_number": None,
        "module": ".agents/skills/document-skills-xlsx/recalc.py",
        "description": "Excel with formulas & recalculation",
        "implements": ["recalc.py"],
        "issue": "Not imported. Could enhance XLSX export with formulas.",
    },
    "document-skills-docx": {
        "status": PROMPT_ONLY, "skill_number": None,
        "description": "Word document creation/tracked changes",
        "priority": "low",
        "could_implement": "DOCX forensic report export",
    },
    "document-skills-pptx": {
        "status": PROMPT_ONLY, "skill_number": None,
        "description": "PowerPoint creation from HTML",
        "priority": "low",
        "could_implement": "PPTX presentation export for forensic briefings",
    },
    "domain-name-brainstormer": {
        "status": PROMPT_ONLY, "skill_number": None,
        "description": "Creative naming & brainstorming",
        "priority": "low",
        "could_implement": "AI prompt skill, no backend code needed",
    },
    "content-research-writer": {
        "status": PROMPT_ONLY, "skill_number": None,
        "description": "Brainstorming, research, collaborative writing",
        "priority": "low",
        "could_implement": "AI prompt skill, no backend code needed",
    },
    "file-organizer": {
        "status": PROMPT_ONLY, "skill_number": None,
        "description": "File management, duplicate detection",
        "priority": "low",
        "could_implement": "AI prompt skill, no backend code needed",
    },
    "incident-response-expert": {
        "status": PROMPT_ONLY, "skill_number": None,
        "description": "IR methodology and playbooks",
        "priority": "low",
        "could_implement": "AI prompt skill, no backend code needed",
    },
    "agent-skill-optimizer": {
        "status": PROMPT_ONLY, "skill_number": None,
        "description": "Skill optimization and improvement advisor",
        "priority": "low",
        "could_implement": "AI prompt skill, no backend code needed",
    },

    # ═══════════════════════════════════════════════════════════════════════
    # QA / DIAGNOSTICS — Always-active testing & validation skills
    # ═══════════════════════════════════════════════════════════════════════

    "chronos_chart_diagnostics": {
        "status": ACTIVE, "skill_number": None,
        "module": "engine.analyzer",
        "description": "Chart QA — Validates chart visibility, cardinality, titles, and export rendering",
        "implements": ["Smart fallback for low-cardinality columns", "Dynamic chart_title"],
        "used_by": ["engine/analyzer.py:_compute_distributions"],
    },
    "chronos_export_testing": {
        "status": ACTIVE, "skill_number": None,
        "module": ".agents/skills/chronos_export_testing",
        "description": "Export QA — 10 comprehensive export tests for PDF, HTML, CSV, XLSX, JSON",
        "implements": ["Export validation checklists"],
    },
    "chronos_filter_diagnostics": {
        "status": ACTIVE, "skill_number": None,
        "module": ".agents/skills/chronos_filter_diagnostics",
        "description": "Filter QA — Validates filter propagation, TTP updates, cache symptoms",
        "implements": ["Filter + TTP diagnostic checklists"],
    },
    "chronos_polars_compat": {
        "status": ACTIVE, "skill_number": None,
        "module": ".agents/skills/chronos_polars_compat",
        "description": "Polars API compat guard — prevents deprecated params in write_excel/write_json",
        "implements": ["xlsxwriter-direct pattern for XLSX exports", "Deprecated param checklist"],
    },
}


# ── Helper Functions ────────────────────────────────────────────────────────

def get_skills_by_status(status: str) -> Dict[str, Dict]:
    """Return all skills with a given status."""
    return {k: v for k, v in SKILL_REGISTRY.items() if v["status"] == status}


def get_skill_summary() -> Dict[str, int]:
    """Return count of skills per status category."""
    summary = {}
    for skill in SKILL_REGISTRY.values():
        s = skill["status"]
        summary[s] = summary.get(s, 0) + 1
    return summary


def get_high_priority_prompts() -> Dict[str, Dict]:
    """Return prompt-only skills marked as high priority for future implementation."""
    return {
        k: v for k, v in SKILL_REGISTRY.items()
        if v["status"] == PROMPT_ONLY and v.get("priority") == "high"
    }


def print_registry_report():
    """Print a human-readable report of the skill registry."""
    summary = get_skill_summary()
    total = sum(summary.values())
    print(f"\n{'='*60}")
    print(f"  CHRONOS-DFIR SKILL REGISTRY — {total} skills total")
    print(f"{'='*60}")
    for status, count in sorted(summary.items()):
        pct = (count / total) * 100
        print(f"  {status:15s}: {count:3d} ({pct:.0f}%)")
    print(f"{'='*60}")

    high = get_high_priority_prompts()
    if high:
        print(f"\n  HIGH PRIORITY (prompt_only → could become active):")
        for name, info in high.items():
            print(f"    • {name}: {info.get('could_implement', 'TBD')}")
    print()


if __name__ == "__main__":
    print_registry_report()
