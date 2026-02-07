import pandas as pd
import json

# ================= CONFIG =================
MAX_AI_PIVOTS = 3
MIN_SCORE_THRESHOLD = 6
SECONDS_PER_PIVOT = 90
HISTORICAL_LOOKBACK_HOURS = 24

MANUAL_MTTR_MINUTES = 22.0  # from Phase 5 (use your measured value)

HIGH_SIGNAL_KEYWORDS = {
    "mimikatz": ("T1003", "Credential Dumping"),
    "invoke-mimikatz": ("T1003", "Credential Dumping"),
    "dumpcreds": ("T1003", "Credential Dumping"),
}

MEDIUM_SIGNAL_KEYWORDS = [
    "powershell",
    "cmd.exe",
    "rundll32",
]

ENVIRONMENT_NOISE = [
    "git.exe",
    "mklink",
    "atomic-red-team",
    "atomicredteam",
]

# ================= LOAD DATA =================
def load_events():
    df = pd.read_csv("../output/attack_events.csv", low_memory=False)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["event_id"] = df["event_id"].astype(str)
    df = df[df["event_id"].isin(["4688", "4104"])]
    return df.dropna(subset=["timestamp"])

# ================= HELPERS =================
def extract_process(command):
    command = str(command).lower()
    for p in ["powershell.exe", "cmd.exe", "rundll32.exe"]:
        if p in command:
            return p
    return "unknown"

def is_environment_noise(command):
    command = command.lower()
    return any(n in command for n in ENVIRONMENT_NOISE)

def score_pivot(command):
    command = command.lower()
    score = 0
    reasons = []
    techniques = set()

    for k, (tid, tname) in HIGH_SIGNAL_KEYWORDS.items():
        if k in command:
            score += 5
            reasons.append(f"high-signal: {k}")
            techniques.add(f"{tid} – {tname}")

    for k in MEDIUM_SIGNAL_KEYWORDS:
        if k in command:
            score += 2
            reasons.append(f"medium-signal: {k}")

    return score, reasons, list(techniques)

# ================= AI DECISION ENGINE =================
def build_ai_decision(df):
    pivots = []

    for _, row in df.iterrows():
        cmd = str(row.get("CommandLine", ""))
        if is_environment_noise(cmd):
            continue

        score, reasons, techniques = score_pivot(cmd)
        if score >= MIN_SCORE_THRESHOLD:
            pivots.append({
                "timestamp": row["timestamp"],
                "process": extract_process(cmd),
                "command": cmd,
                "score": score,
                "reasons": reasons,
                "techniques": techniques
            })

    ai_df = pd.DataFrame(pivots).sort_values(
        ["score", "timestamp"], ascending=[False, True]
    )

    top_pivots = ai_df.head(MAX_AI_PIVOTS)

    max_score = top_pivots["score"].max()

    if max_score >= 15:
        decision = "ESCALATE"
        confidence = "HIGH"
    elif max_score >= 8:
        decision = "INVESTIGATE FURTHER"
        confidence = "MEDIUM"
    else:
        decision = "LIKELY FALSE POSITIVE"
        confidence = "LOW"

    return top_pivots, decision, confidence

# ================= HISTORICAL CONTEXT =================
def historical_context(df, pivot_command, current_time):
    lookback_start = current_time - pd.Timedelta(hours=HISTORICAL_LOOKBACK_HOURS)

    history = df[
        (df["timestamp"] >= lookback_start) &
        (df["timestamp"] < current_time) &
        (df["CommandLine"].astype(str).str.contains(
            pivot_command.split(" ")[0], case=False, na=False
        ))
    ]

    return {
        "count": len(history),
        "first_seen": history["timestamp"].min(),
        "last_seen": history["timestamp"].max()
    }

# ================= HOST RISK =================
def calculate_host_risk(pivots):
    risk = 0
    for _, p in pivots.iterrows():
        if p["score"] >= 15:
            risk += 10
        elif p["score"] >= 8:
            risk += 5
        else:
            risk += 2

    if risk >= 15:
        level = "HIGH"
    elif risk >= 8:
        level = "MEDIUM"
    else:
        level = "LOW"

    return risk, level

# ================= RECOMMENDATIONS =================
def recommended_next_steps(decision):
    if decision == "ESCALATE":
        return [
            "Isolate affected host",
            "Collect LSASS-related telemetry",
            "Review recent authentication failures",
            "Check lateral movement indicators"
        ]
    if decision == "INVESTIGATE FURTHER":
        return [
            "Review parent process tree",
            "Correlate with network connections",
            "Check user activity context"
        ]
    return [
        "Monitor for recurrence",
        "Document justification for closure"
    ]

# ================= MTTR =================
def calculate_mttr(manual_minutes, ai_pivots):
    ai_minutes = (len(ai_pivots) * SECONDS_PER_PIVOT) / 60
    reduction = ((manual_minutes - ai_minutes) / manual_minutes) * 100
    return ai_minutes, round(reduction, 2)

# ================= JSON SAFETY =================
def make_json_safe(obj):
    # Handle pandas NaT
    if obj is pd.NaT:
        return None

    # Handle pandas Timestamp
    if isinstance(obj, pd.Timestamp):
        return obj.isoformat()

    # Handle numpy / pandas scalar types
    if hasattr(obj, "item"):
        return obj.item()

    # Handle dict
    if isinstance(obj, dict):
        return {k: make_json_safe(v) for k, v in obj.items()}

    # Handle list
    if isinstance(obj, list):
        return [make_json_safe(v) for v in obj]

    return obj


# ================= MAIN =================
if __name__ == "__main__":
    df = load_events()

    pivots, decision, confidence = build_ai_decision(df)
    primary_pivot = pivots.iloc[0]

    history = historical_context(
        df,
        primary_pivot["command"],
        primary_pivot["timestamp"]
    )

    host_risk_score, host_risk_level = calculate_host_risk(pivots)
    steps = recommended_next_steps(decision)

    ai_mttr, reduction = calculate_mttr(MANUAL_MTTR_MINUTES, pivots)

    # ----------- CONSOLE OUTPUT -----------
    print("\n" + "="*55)
    print("               INCIDENT SUMMARY")
    print("="*55)
    print(f"Decision           : {decision}")
    print(f"Confidence         : {confidence}")
    print(f"Host Risk Level    : {host_risk_level}")
    print(f"Host Risk Score    : {host_risk_score}")
    print(f"Primary Technique  : {', '.join(primary_pivot['techniques'])}")

    print("\n" + "-"*55)
    print("TOP INDICATOR")
    print("-"*55)
    print(f"Process            : {primary_pivot['process']}")
    print(f"Command            : {primary_pivot['command']}")
    print(f"Score              : {primary_pivot['score']}")
    print(f"Why                : {', '.join(primary_pivot['reasons'])}")

    print("\n" + "-"*55)
    print("HISTORICAL CONTEXT (Last 24h)")
    print("-"*55)
    print(f"Occurrences        : {history['count']}")
    print(f"First Seen         : {history['first_seen']}")
    print(f"Last Seen          : {history['last_seen']}")

    print("\n" + "-"*55)
    print("RECOMMENDED NEXT ACTIONS")
    print("-"*55)
    for s in steps:
        print(f"- {s}")

    print("\n" + "-"*55)
    print("MTTR IMPACT")
    print("-"*55)
    print(f"Manual MTTR        : {MANUAL_MTTR_MINUTES} minutes")
    print(f"AI-Assisted MTTR   : {ai_mttr:.2f} minutes")
    print(f"Reduction          : {reduction}%")
    print("="*55)

    # ----------- INCIDENT DOSSIER -----------
    evidence = {
        "decision": decision,
        "confidence": confidence,
        "host_risk": {
            "score": host_risk_score,
            "level": host_risk_level
        },
        "primary_indicator": make_json_safe(primary_pivot.to_dict()),
        "historical_context": make_json_safe(history),
        "mitre_techniques": list(set(sum(pivots["techniques"].tolist(), []))),
        "recommended_actions": steps,
        "manual_mttr_minutes": MANUAL_MTTR_MINUTES,
        "ai_mttr_minutes": ai_mttr,
        "mttr_reduction_percent": reduction
    }

    with open("../output/incident_dossier.json", "w") as f:
        json.dump(make_json_safe(evidence), f, indent=2)
