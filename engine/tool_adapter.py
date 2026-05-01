# ./MetaTron/engine/tool_adapter.py
# MetaTron Security Tool - Tool Adapter
# Created by David Kistner (Unconditional Love) at GlyphicMind Solutions LLC.



#system imports
import subprocess, json
from pathlib import Path

#pathing
SETTINGS = json.loads((Path(__file__).resolve().parents[1] / "config" / "settings.json").read_text())



# =================================
# Run Helpers Section
# =================================
# ---------------
# Connect
# ---------------
def _run(cmd: list[str], timeout: int = 120) -> str:
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout
        )
        out = result.stdout.strip()
        err = result.stderr.strip()
        if out and err:
            return out + "\n[STDERR]\n" + err
        if out:
            return out
        if err:
            return err
        return "[NO OUTPUT]"
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] {' '.join(cmd)}"
    except FileNotFoundError:
        return f"[MISSING TOOL] {cmd[0]} is not installed."
    except Exception as e:
        return f"[EXCEPTION] {e}"

# ---------------
# Run Nmap
# ---------------
def run_nmap(target: str) -> str:
    return _run(["nmap", "-sV", "-sC", "-T4", "--open", target], timeout=180)

# ---------------
# Run Whois
# ---------------
def run_whois(target: str) -> str:
    return _run(["whois", target], timeout=30)

# ---------------
# Run WhatWeb
# ---------------
def run_whatweb(target: str) -> str:
    return _run(["whatweb", "-a", "3", target], timeout=60)

# ------------------
# Run Curl Headers
# ------------------
def run_curl_headers(target: str) -> str:
    http = _run(["curl", "-sI", "--max-time", "10", "--location", f"http://{target}"], timeout=20)
    https = _run(["curl", "-sI", "--max-time", "10", "--location", "-k", f"https://{target}"], timeout=20)
    return f"[HTTP]\n{http}\n\n[HTTPS]\n{https}"

# ---------------
# Run Dig
# ---------------
def run_dig(target: str) -> str:
    a   = _run(["dig", "+short", "A",   target], timeout=15)
    mx  = _run(["dig", "+short", "MX",  target], timeout=15)
    ns  = _run(["dig", "+short", "NS",  target], timeout=15)
    txt = _run(["dig", "+short", "TXT", target], timeout=15)
    return f"[A]\n{a}\n\n[MX]\n{mx}\n\n[NS]\n{ns}\n\n[TXT]\n{txt}"

# ---------------
# Run Nikto
# ---------------
def run_nikto(target: str) -> str:
    return _run(["nikto", "-h", target, "-nointeractive"], timeout=300)

# ---------------
# Run Recon
# ---------------
def run_recon(target: str) -> str:
    sections = []
    sections.append("=== NMAP ===")
    sections.append(run_nmap(target))
    sections.append("\n=== WHOIS ===")
    sections.append(run_whois(target))
    sections.append("\n=== WHATWEB ===")
    sections.append(run_whatweb(target))
    sections.append("\n=== CURL HEADERS ===")
    sections.append(run_curl_headers(target))
    sections.append("\n=== DNS (DIG) ===")
    sections.append(run_dig(target))

    if SETTINGS["tools"].get("enable_nikto", False):
        sections.append("\n=== NIKTO ===")
        sections.append(run_nikto(target))

    return "\n".join(sections)

