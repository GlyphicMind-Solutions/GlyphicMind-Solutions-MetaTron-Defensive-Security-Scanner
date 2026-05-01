# ./MetaTron/engine/risk_engine.py
# MetaTron Security Tool - Risk Scoring Engine
# Created by David Kistner (Unconditional Love) at GlyphicMind Solutions LLC.



#system imports
import json, re
from pathlib import Path


# -------------------------
# Load Threat Databas
# -------------------------
def load_threat_db():
    db_path = Path(__file__).resolve().parent.parent / "data" / "threat_signatures.json"
    if not db_path.exists():
        return {}
    with open(db_path, "r", encoding="utf-8") as f:
        return json.load(f)

# -----------------------
# Detect Services
# -----------------------
def detect_services(recon_text):
    services = set()

    patterns = {
        "apache": r"Apache\/([\d\.]+)",
        "nginx": r"nginx\/([\d\.]+)",
        "ssh": r"OpenSSH_([\d\.]+)",
        "smb": r"SMBv?(\d)",
        "ftp": r"FTP",
        "dns": r"DNS",
        "rdp": r"RDP",
        "snmp": r"SNMP",
        "mysql": r"MySQL",
        "postgres": r"PostgreSQL",
        "redis": r"Redis",
        "mongodb": r"MongoDB",
        "telnet": r"Telnet"
    }

    versions = {}

    for service, pattern in patterns.items():
        match = re.search(pattern, recon_text, re.IGNORECASE)
        if match:
            services.add(service)
            if match.groups():
                versions[service] = match.group(1)

    return services, versions

# -----------------------
# Count Open Ports
# -----------------------
def count_open_ports(recon_text):
    # Matches "PORT STATE SERVICE"
    matches = re.findall(r"(\d{1,5})\/tcp\s+open", recon_text)
    return len(matches)

# -----------------------------------------------
# Match threat signatures
# -----------------------------------------------
def match_threats(services, versions, threat_db):
    matches = []

    for service in services:
        if service not in threat_db:
            continue

        entry = threat_db[service]

        # Version-based threats
        if "versions" in entry and service in versions:
            ver = versions[service]
            if ver in entry["versions"]:
                matches.append(entry["versions"][ver])

        # Config-based threats
        if "config" in entry:
            for key, val in entry["config"].items():
                if key in versions.get(service, ""):
                    matches.append(val)

        # Defaults
        if "defaults" in entry:
            for key, val in entry["defaults"].items():
                if key.lower() in " ".join(services).lower():
                    matches.append(val)

    return matches

# -----------------------------------------------
# Compute Balanced Risk Score (0–100)
# -----------------------------------------------
def compute_risk_score(recon_text, llm_vulns):
    threat_db = load_threat_db()

    services, versions = detect_services(recon_text)
    open_ports = count_open_ports(recon_text)
    threat_matches = match_threats(services, versions, threat_db)

    #-Balanced Weights-#
    score = 0

    # Open ports (max 20 points)
    score += min(open_ports * 2, 20)

    # High-risk services (max 25 points)
    high_risk_services = {"smb", "rdp", "telnet", "ftp"}
    score += min(len(services & high_risk_services) * 8, 25)

    # Threat signature matches (max 30 points)
    score += min(len(threat_matches) * 6, 30)

    # LLM vulnerabilities (max 25 points)
    score += min(len(llm_vulns) * 5, 25)

    # Cap at 100
    score = min(score, 100)

    # Severity Mapping
    if score >= 85:
        severity = "CRITICAL"
    elif score >= 70:
        severity = "HIGH"
    elif score >= 40:
        severity = "MEDIUM"
    elif score >= 15:
        severity = "LOW"
    else:
        severity = "UNKNOWN"

    return {
        "score": score,
        "severity": severity,
        "services": list(services),
        "versions": versions,
        "open_ports": open_ports,
        "threat_matches": threat_matches,
        "vuln_count": len(llm_vulns)
    }

