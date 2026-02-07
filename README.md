🛡️ AI-Assisted SOC Investigation Engine

An analyst-in-the-loop SOC investigation engine that ingests native Windows telemetry, reconstructs investigation timelines, enriches alerts with historical context, and uses explainable AI-assisted logic to recommend investigation pivots, response actions, and escalation decisions — with measurable MTTR reduction.

---

🔍 Problem Statement

Security Operations Centers (SOCs) struggle with:
- High alert volume and noisy telemetry
- Analyst decision fatigue
- Inconsistent investigation paths
- High Mean Time To Respond (MTTR)

Most AI SOC tools jump straight to automation without modeling how analysts actually investigate.
---

💡 Solution Overview

This project models real SOC workflows first, then applies AI-assisted reasoning to reduce analyst effort while preserving explainability and control.

The system:
- Parses native Windows EVTX logs (no EDR required)
- Builds realistic investigation timelines
- Models manual MTTR
- Applies AI-assisted pivot ranking and decision logic
- Produces SOC-ready incident dossiers with recommended next steps

---

🧠 Architecture Flow

Windows Security & PowerShell Logs (EVTX)
                ↓
        Parsing & Normalization
                ↓
     Baseline vs Attack Separation
                ↓
     Investigation Timeline (MTTR Baseline)
                ↓
   Context Enrichment & Noise Reduction
                ↓
   AI-Assisted Pivot Ranking (Explainable)
                ↓
 Decision + Confidence + MITRE Mapping
                ↓
   Incident Dossier (JSON Output)

---

🧪 Validation Methodology

- Attack Simulation: Atomic Red Team (Windows techniques)
- Telemetry Sources:
    - Security Event Log (4688 – Process Creation)
    - PowerShell Operational Log (4104 – Script Block Logging)
- Environment: Windows 11, Defender enabled
- Approach:
    - Measure realistic manual MTTR
    - Compare against AI-assisted investigation flow

---

📊 Results & Metrics
Metric          	      Value
Manual MTTR      	      ~22 minutes
AI-Assisted MTTR	      ~1.5 minutes
MTTR Reduction	        ~93%
Analyst Pivots	        ~15 → 1–3

---

🚨 Example AI Output
Decision           : ESCALATE
Confidence         : HIGH
Host Risk Level    : MEDIUM
Primary Technique  : T1003 – Credential Dumping

Top Indicator:
- Invoke-Mimikatz PowerShell execution

Recommended Actions:
- Isolate affected host
- Collect LSASS telemetry
- Review authentication failures

---

📁 Incident Dossier Output

Each investigation generates a SOC-ready JSON artifact:

{
  "decision": "ESCALATE",
  "confidence": "HIGH",
  "host_risk": {
    "score": 10,
    "level": "MEDIUM"
  },
  "mitre_techniques": [
    "T1003 – Credential Dumping"
  ],
  "recommended_actions": [
    "Isolate affected host",
    "Collect LSASS-related telemetry"
  ],
  "mttr_reduction_percent": 93.18
}

---

🧩 Key Features

- Native Windows log parsing (EVTX)
- Investigation timeline reconstruction
- Manual MTTR modeling
- Historical event correlation (24-hour lookback)
- Host-level risk accumulation
- Explainable AI-assisted pivot ranking
- MITRE ATT&CK technique mapping
- Analyst-in-the-loop decision support
- SOC-ready incident dossiers

---

⚙️ Setup & Usage

Install dependencies
pip install -r requirements.txt

Run pipeline
python parser/normalize.py
python parser/timeline.py
python parser/enrichment.py
python parser/ai_pivot_engine.py

---

🔒 Disclaimer

This project is for defensive security research and educational purposes only.

---

🚀 Future Enhancements

- Local LLM reasoning (optional)
- SOAR platform integration
- Multi-host correlation
- HTML incident reports

---

👤 Author
Arham
Security Engineering / SOC Automation
