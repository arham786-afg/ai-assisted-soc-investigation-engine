import pandas as pd

PIVOT_DELAY_SECONDS = 90
MAX_PIVOTS = 20
SUSPICIOUS_KEYWORDS = [
    "atomic",
    "invoke-atomic",
    "powershell",
    "cmd.exe",
    "rundll32",
    "mimikatz",
]

def load_attack_events():
    df = pd.read_csv("../output/attack_events.csv", low_memory=False)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["event_id"] = df["event_id"].astype(str)
    return df.dropna(subset=["timestamp"])

def reduce_noise(df):
    key_cols = ["ProcessName", "CommandLine"]

    for col in key_cols:
        if col not in df.columns:
            df[col] = "UNKNOWN"

    reduced = (
        df.groupby(key_cols, dropna=False)
        .agg(
            first_seen=("timestamp", "min"),
            count=("timestamp", "count"),
        )
        .reset_index()
        .sort_values("first_seen")
    )

    return reduced

def score_suspicious(row):
    text = f"{row['ProcessName']} {row['CommandLine']}".lower()
    return any(k in text for k in SUSPICIOUS_KEYWORDS)

def simulate_human_pivots(reduced_df):
    reduced_df = reduced_df.copy()
    reduced_df["suspicious"] = reduced_df.apply(score_suspicious, axis=1)

    # Analyst prioritizes suspicious pivots first
    prioritized = pd.concat([
        reduced_df[reduced_df["suspicious"] == True],
        reduced_df[reduced_df["suspicious"] == False],
    ])

    # Analyst never looks at more than MAX_PIVOTS
    pivots = prioritized.head(MAX_PIVOTS).copy()

    pivots["pivot_time"] = pivots["first_seen"]

    for i in range(1, len(pivots)):
        pivots.loc[pivots.index[i], "pivot_time"] = (
            pivots.loc[pivots.index[i - 1], "pivot_time"]
            + pd.Timedelta(seconds=PIVOT_DELAY_SECONDS)
        )

    return pivots

def calculate_manual_mttr(pivot_df):
    alert_start = pivot_df.iloc[0]["first_seen"]
    decision_time = pivot_df.iloc[-1]["pivot_time"]
    mttr_minutes = (decision_time - alert_start).total_seconds() / 60
    return mttr_minutes, alert_start, decision_time

if __name__ == "__main__":
    df = load_attack_events()
    df = df[df["event_id"].isin(["4688", "4104"])]

    reduced = reduce_noise(df)
    pivot_df = simulate_human_pivots(reduced)

    mttr, alert_start, decision_time = calculate_manual_mttr(pivot_df)

    print("=== MANUAL INVESTIGATION (REALISTIC) ===")
    print(f"Unique pivots reviewed: {len(pivot_df)}")
    print(f"Alert start: {alert_start}")
    print(f"Decision time: {decision_time}")
    print(f"Manual MTTR (minutes): {mttr:.2f}")
