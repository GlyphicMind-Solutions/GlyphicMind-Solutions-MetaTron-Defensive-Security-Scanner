# ./MetaTron/engine/hardening_engine.py
# MetaTron Security Tool - Hardening Checklist Engine
# Created by David Kistner (Unconditional Love) at GlyphicMind Solutions LLC.



#system imports
from typing import List, Dict



# ---------------------------
# Build Hardening Checklist
# ---------------------------
def build_hardening_checklist(
    services: List[str],
    versions: Dict[str, str],
    threat_matches: List[Dict],
    llm_vulns: List[Dict]
) -> List[str]:
    """
    Build a consolidated hardening checklist based on:
      - detected services
      - service versions
      - threat signature matches
      - LLM-identified vulnerabilities

    Returns a de-duplicated, ordered list of hardening actions.
    """

    checklist: List[str] = []

    # 1) Service-based hardening
    checklist.extend(_service_based_hardening(services))

    # 2) Version-based / threat-based hardening
    checklist.extend(_threat_based_hardening(threat_matches))

    # 3) LLM vulnerability-based hardening
    checklist.extend(_llm_based_hardening(llm_vulns))

    # 4) Generic baseline hardening (always useful)
    checklist.extend(_baseline_hardening())

    # De-duplicate while preserving order
    seen = set()
    final = []
    for item in checklist:
        if not item:
            continue
        if item not in seen:
            seen.add(item)
            final.append(item)

    return final

# ------------------------------
# Service-based Hardening
# ------------------------------
def _service_based_hardening(services: List[str]) -> List[str]:
    items: List[str] = []
    s = set(s.lower() for s in services)

    if "ssh" in s:
        items.append("Disable password authentication for SSH and enforce key-based authentication only.")
        items.append("Restrict SSH access to specific management IP ranges using firewall rules.")
        items.append("Change the default SSH port only as a minor obfuscation, not as a primary control.")

    if "smb" in s:
        items.append("Disable SMBv1 and older SMB protocols; use SMBv3 where possible.")
        items.append("Restrict SMB access to internal, trusted networks only.")
        items.append("Require strong authentication for SMB shares and avoid anonymous access.")

    if "ftp" in s:
        items.append("Replace FTP with SFTP or FTPS to avoid plaintext credentials and data.")
        items.append("Disable anonymous FTP access unless absolutely required and tightly controlled.")

    if "rdp" in s:
        items.append("Enable Network Level Authentication (NLA) for all RDP endpoints.")
        items.append("Restrict RDP access to VPN or specific jump hosts instead of exposing it directly to the internet.")

    if "http" in s or "https" in s or "apache" in s or "nginx" in s:
        items.append("Enable HTTP security headers (HSTS, X-Frame-Options, X-Content-Type-Options, CSP) where applicable.")
        items.append("Hide detailed server version banners in HTTP responses to reduce fingerprinting.")
        items.append("Ensure TLS is configured to disable outdated protocols (TLS 1.0/1.1) and weak ciphers.")

    if "dns" in s:
        items.append("Ensure DNS servers are not open resolvers and restrict recursion to internal clients.")
        items.append("Implement SPF, DKIM, and DMARC records for domains handling email.")
        items.append("Harden zone transfers by restricting them to authorized secondary DNS servers only.")

    if "snmp" in s:
        items.append("Disable SNMP v1/v2c or migrate to SNMPv3 with authentication and encryption.")
        items.append("Change default SNMP community strings and restrict SNMP access to management networks.")

    if "mysql" in s or "postgres" in s:
        items.append("Restrict database access to application servers and trusted admin hosts only.")
        items.append("Enforce strong authentication and avoid default or blank database passwords.")
        items.append("Ensure database ports are not exposed directly to the internet.")

    if "redis" in s or "mongodb" in s:
        items.append("Bind Redis/MongoDB to localhost or internal interfaces only; avoid public exposure.")
        items.append("Enable authentication and authorization for Redis/MongoDB where supported.")
        items.append("Use firewall rules to restrict access to cache and NoSQL services.")

    if "telnet" in s:
        items.append("Disable Telnet and replace it with SSH for secure remote access.")

    return items

# -----------------------------------------------
# Threat-based Hardening (from threat_matches)
# -----------------------------------------------
def _threat_based_hardening(threat_matches: List[Dict]) -> List[str]:
    items: List[str] = []

    for match in threat_matches:
        # Each match is expected to have at least: severity, description, and optionally 'hardening'
        hardening = match.get("hardening")
        if hardening:
            if isinstance(hardening, list):
                items.extend(hardening)
            elif isinstance(hardening, str):
                items.append(hardening)

    return items

# -----------------------------------------------
# LLM-based hardening (from vulnerabilities)
# -----------------------------------------------
def _llm_based_hardening(llm_vulns: List[Dict]) -> List[str]:
    items: List[str] = []

    for v in llm_vulns:
        fix = v.get("recommended_fix") or v.get("fix") or v.get("mitigation")
        if fix:
            items.append(fix)

    return items

# -----------------------------------------------
# Baseline hardening (always useful)
# -----------------------------------------------
def _baseline_hardening() -> List[str]:
    return [
        "Apply all available security patches and updates for the operating system and installed services safely.",
        "Enforce strong, unique passwords and consider multi-factor authentication where supported.",
        "Limit exposed services to only what is strictly necessary for the system's role.",
        "Implement host-based firewall rules to restrict inbound and outbound traffic to required ports only.",
        "Enable detailed logging for authentication, network access, and administrative actions.",
        "Regularly review logs for suspicious activity or repeated failed login attempts.",
        "Ensure regular, tested backups exist for critical systems and data.",
        "Document the system's purpose, exposed services, and applied hardening measures for future audits."
    ]

