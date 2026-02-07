import pandas as pd

ATTACK_EVENTS = ["4688", "4104"]
SUSPICIOUS_KEYWORDS = [
    "mimikatz",
    "atomic",
    "invoke-atomic",
    "powershell",
    "cmd.exe",
    "rundll32",
]

def load_events(path):
    df = pd.read_csv(path, low_memory=False)

    # Normalize types
    df["event_id"] = df["event_id"].astype(str)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    df = df.dropna(subset=["timestamp", "event_id"])
    return df.sort_values("timestamp")

def mark_suspicious(df):
    def is_suspicious(row):
        text = " ".join([
            str(row.get("CommandLine", "")),
            str(row.get("ScriptBlockText", "")),
            str(row.get("ProcessName", "")),
        ]).lower()

        return any(k in text for k in SUSPICIOUS_KEYWORDS)

    df = df.copy()
    df.loc[:, "suspicious"] = df.apply(is_suspicious, axis=1)

    return df

def build_timeline(df):
    df = df[df["event_id"].isin(ATTACK_EVENTS)]

    print(f"[DEBUG] Events after ATT&CK filter: {len(df)}")

    if df.empty:
        return df

    return mark_suspicious(df)

def calculate_mttr(timeline):
    if timeline.empty:
        print("[WARN] Timeline is empty after filtering")
        return None, None, None

    alert_start = timeline.iloc[0]["timestamp"]
    pivot_events = timeline[timeline["suspicious"] == True]

    if pivot_events.empty:
        print("[WARN] No suspicious pivot events found")
        return None, alert_start, None

    first_pivot = pivot_events.iloc[0]["timestamp"]
    mttr_minutes = (first_pivot - alert_start).total_seconds() / 60

    return mttr_minutes, alert_start, first_pivot

if __name__ == "__main__":
    attack_df = load_events("../output/attack_events.csv")
    timeline = build_timeline(attack_df)

    mttr, alert_start, first_pivot = calculate_mttr(timeline)

    print("\n=== BASELINE INVESTIGATION METRICS ===")
    print(f"Alert start: {alert_start}")
    print(f"First pivot: {first_pivot}")
    print(f"Baseline MTTR (minutes): {mttr}")
