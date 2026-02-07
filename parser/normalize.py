from evtx_parser import parse_evtx
import pandas as pd

def normalize():
    baseline_sec = parse_evtx(
        "../logs/baseline/security.evtx", "baseline_security"
    )
    baseline_ps = parse_evtx(
        "../logs/baseline/powershell.evtx", "baseline_powershell"
    )

    attack_sec = parse_evtx(
        "../logs/attacks/security_attacks.evtx", "attack_security"
    )
    attack_ps = parse_evtx(
        "../logs/attacks/powershell_attacks.evtx", "attack_powershell"
    )

    baseline = pd.concat([baseline_sec, baseline_ps])
    attacks = pd.concat([attack_sec, attack_ps])

    baseline.to_csv("../output/baseline_events.csv", index=False)
    attacks.to_csv("../output/attack_events.csv", index=False)

if __name__ == "__main__":
    normalize()
