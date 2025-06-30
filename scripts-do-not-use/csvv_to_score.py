#!/usr/bin/env python3
import sys
import math

def round_up(value: float) -> float:
    return math.ceil(value * 10) / 10

def parse_vector(vector: str) -> dict:
    if vector.startswith("CVSS:4.0/"):
        vector = vector[9:]
    return dict(part.split(":") for part in vector.split("/"))

def cvss_v4_score(metrics: dict) -> float:
    # Exploitability sub-score
    AV = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.20}[metrics['AV']]
    AC = {'L': 0.77, 'H': 0.44}[metrics['AC']]
    AT = {'N': 0.85, 'P': 0.62}[metrics['AT']]
    VC = {'N': 0.85, 'L': 0.62, 'H': 0.44}[metrics['VC']]
    exploitability = 8.22 * AV * AC * AT * VC

    # Impact sub-score
    SC = {'H': 0.56, 'L': 0.22, 'N': 0.0}[metrics['SC']]
    SI = {'H': 0.56, 'L': 0.22, 'N': 0.0}[metrics['SI']]
    SA = {'H': 0.56, 'L': 0.22, 'N': 0.0}[metrics['SA']]
    impact = 6.42 * (1 - (1 - SC)*(1 - SI)*(1 - SA))

    # Base Score
    score = impact + exploitability
    return round_up(min(score, 10.0))

def cvss_v4_rating(score: float) -> str:
    if score == 0.0:
        return "NONE"
    elif score < 4.0:
        return "LOW"
    elif score < 7.0:
        return "MEDIUM"
    elif score < 9.0:
        return "HIGH"
    else:
        return "CRITICAL"

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 cvss_v4.py 'CVSS:4.0/AV:N/AC:L/AT:N/VC:N/SC:H/SI:H/SA:H'")
        sys.exit(1)

    vector = sys.argv[1]
    try:
        metrics = parse_vector(vector)
        score = cvss_v4_score(metrics)
        rating = cvss_v4_rating(score)
        print(f"{score:.1f} {rating}")
    except Exception as e:
        print(f"Error parsing vector: {e}")
        sys.exit(2)

if __name__ == "__main__":
    main()
