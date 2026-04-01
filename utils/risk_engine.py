def calculate_risk(attack_type):

    risk_map = {
        "DDoS": "CRITICAL",
        "Brute Force": "HIGH",
        "SQL Injection": "HIGH",
        "XSS": "MEDIUM",
        "Port Scan": "LOW",
        "none": "SAFE"
    }

    return risk_map.get(attack_type, "UNKNOWN")