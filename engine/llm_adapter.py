# ./MetaTron/engine/llm_adapter.py
# MetaTron Security Tool - Intelligence-Aware LLM Adapter
# Created by David Kistner (Unconditional Love) at GlyphicMind Solutions LLC.

# system imports
import json
from pathlib import Path

# local imports
from prompt.prompt_builder import PromptBuilder
from engine.risk_engine import compute_risk_score
from engine.hardening_engine import build_hardening_checklist
from .llm_parsers import (
    parse_vulnerabilities,
    parse_exploits,
    parse_risk_level,
    parse_summary
)

# load settings
SETTINGS = json.loads((Path(__file__).resolve().parents[1] / "config" / "settings.json").read_text())

# initialize prompt builder
prompt_builder = PromptBuilder()


# ---------------------------------------------------------
# Build intelligence context block for the LLM
# ---------------------------------------------------------
def _build_intelligence_block(intel: dict) -> str:
    return f"""
===========================
INTELLIGENCE CONTEXT
===========================
Services Detected: {intel['services']}
Versions: {intel['versions']}
Open Ports: {intel['open_ports']}
Threat Matches: {intel['threat_matches']}
LLM Vulnerability Count: {intel['vuln_count']}

Risk Score: {intel['score']} / 100
Severity: {intel['severity']}
"""

# ---------------------------------------------------------
# Run Analysis (Main Entry Point)
# ---------------------------------------------------------
def run_analysis(llm_engine, raw_scan: str, target: str) -> dict:
    """
    Intelligence-aware analysis pipeline:
      1. Compute risk score + intelligence context
      2. Build model-aware prompt (PromptBuilder)
      3. Inject intelligence block
      4. Run LLM
      5. Parse structured output
      6. Build hardening checklist
      7. Return unified analysis object
    """


    # 1. Compute intelligence context
    intelligence = compute_risk_score(raw_scan, llm_vulns=[])
    # LLM vulnerabilities unknown at this stage → empty list
    intelligence_block = _build_intelligence_block(intelligence)

    # 2. Build model-aware defensive prompt
    model_key = llm_engine.default_key
    base_prompt = prompt_builder.build_prompt(
        target=target,
        raw_scan=raw_scan,
        model_key=model_key
    )

    # 3. Inject intelligence block BEFORE the LLM instructions
    final_prompt = f"{base_prompt}\n\n{intelligence_block}\n"

    # 4. Run LLM
    response = llm_engine.generate(
        prompt=final_prompt,
        model_key=model_key,
        max_tokens=2048
    )

    # 5. Parse structured output
    vulns = parse_vulnerabilities(response)
    exploits = parse_exploits(response)
    risk_level = parse_risk_level(response)
    summary = parse_summary(response)

    # 6. Build hardening checklist
    hardening = build_hardening_checklist(
        services=intelligence["services"],
        versions=intelligence["versions"],
        threat_matches=intelligence["threat_matches"],
        llm_vulns=vulns
    )

    # 7. Return unified analysis object
    return {
        "full_response": response,
        "vulnerabilities": vulns,
        "exploits": exploits,
        "risk_level": risk_level,
        "summary": summary,
        "hardening": hardening,
        "risk_score": intelligence["score"],
        "risk_severity": intelligence["severity"],
        "raw_scan": raw_scan,
        "model_used": model_key
    }

