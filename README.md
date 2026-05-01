# 🛡️ GlyphicMind Solutions — MetaTron — Defensive Security Scanner  

## Summary:
MetaTron is a **next‑generation defensive security scanner** that merges  
traditional recon tooling with **LLM‑driven analysis**, **risk scoring**,  
and **automated hardening recommendations** — all wrapped in a clean,  
scalable **PyQt5 GUI**.

MetaTron is designed for **internal network defense**, rapid assessment,  
and intelligent hardening guidance powered by local GGUF models.

---

## 🚀 Features

### 🔍 Recon Engine
- Nmap‑style port scanning  
- HTTP/HTTPS header checks  
- DNS enumeration  
- Tool availability detection  
- Clipboard‑ready install commands  

### 🧠 LLM Intelligence Engine
- Model‑aware prompt builder  
- Local GGUF model support via `llama-cpp-python`  
- Structured output parsing:
  - Vulnerabilities  
  - Exploits attempted  
  - Risk level  
  - **Numeric risk score (0–100)**  
  - **Hardening checklist**  
  - Summary analysis  

### 🖥️ GUI (PyQt5)
- Fully scalable, maximizable interface  
- Tabs for:
  - Scan  
  - History  
  - Tools  
  - Settings  
- Collapsible sections for clean readability  
- Auto‑scrolling output  
- Dark mode toggle  

### 🗂️ Session Database
- SQLite‑backed session storage  
- View past:
  - Summaries  
  - Vulnerabilities  
  - Fixes  
  - Exploits  
  - Hardening recommendations  

---

## 📦 Project Structure
```
MetaTron/
├── config/               # Settings + model configuration
├── data/                 # SQLite DB + threat signatures
├── engine/               # Core logic (LLM, recon, parsing, risk, hardening)
├── gui/                  # PyQt5 interface
├── models/               # Local GGUF models
├── prompt/               # Model-aware prompt builder
├── metatron.py           # Launcher
├── requirements.txt
└── README.md
```

---

## 🧩 Requirements

#### Install dependencies:

```bash
pip install -r requirements.txt
```
Key components:

 * PyQt5

 * llama-cpp-python

 * PyYAML

 * psutil

 * jsonschema

---

## 🧠 Models
Place your .gguf models in:
```
models/
```
Example:

 * mistral-7b-instruct-v0.2.2.Q4_K_M.gguf

 * gpt-oss-20b-MXFP4.gguf

MetaTron automatically loads the model defined in:
```
config/settings.json
```

---

## ▶️ Running MetaTron
```
python3 metatron.py
```

---

## 🛡️ Defensive‑Only Philosophy
MetaTron is strictly a defensive security tool.
- It does not generate offensive payloads or unauthorized exploitation steps.
 - All analysis focuses on:
  * Detection
  * Risk assessment
  * Hardening
  * Internal validation
  * Secure configuration

---

## 📜 License
© 2026 GlyphicMind Solutions LLC
Created by David Kistner (Unconditional Love)  
All rights reserved.  

#### Contact:
Phone: (913)605-3993  
Email: glyphicmindsolutions@gmail.com
