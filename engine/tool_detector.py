# ./MetaTron/engine/tool_detector.py
# MetaTron Security Tool - Recon Tool Detector
# Created by David Kistner (Unconditional Love) at GlyphicMind Solutions LLC.


#system imports
import shutil

# List of recon tools MetaTron supports
TOOLS = [
    "nmap",
    "whois",
    "whatweb",
    "dig",
    "curl",
    "nikto"
]



# ---------------
# Detect Tools
# ---------------
def detect_tools():
    """
    Detect which recon tools are installed on the system.
    Returns a dictionary mapping tool -> True/False.
    """
    results = {}
    for tool in TOOLS:
        results[tool] = shutil.which(tool) is not None
    return results


# -----------------
# Install Command
# -----------------
def install_command():
    """
    Returns a single-line Linux command to install all recon tools.
    Used by the Tools tab's 'Copy Install Commands' button.
    """
    return "sudo apt install nmap whois whatweb dnsutils curl nikto"

