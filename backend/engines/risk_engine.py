def calculate_risk_score(findings):

    if not findings:
        return {
            "score": 0,
            "grade": "A",
            "label": "Secure",
            "summary": "No security issues detected"
        }

    severity_weights = {
        "CRITICAL": 10,
        "HIGH": 7,
        "MEDIUM": 4,
        "LOW": 2,
        "INFO": 0
    }

    total_score = 0
    max_possible = 0

    severity_count = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0
    }

    for f in findings:

        severity = f.get("severity", "LOW").upper()
        cvss = float(f.get("cvss", 0))
        confidence = float(f.get("confidence", 100))

        base_weight = severity_weights.get(severity, 1)

        cvss_factor = cvss / 10 if cvss > 0 else 0.5

        confidence_factor = confidence / 100

        weighted = base_weight * cvss_factor * confidence_factor

        total_score += weighted
        max_possible += 10

        if severity in severity_count:
            severity_count[severity] += 1

    score = int((total_score / max_possible) * 100)
    score = min(100, max(score, 0))

    if score >= 85:
        grade, label = "F", "Critical Risk"
    elif score >= 70:
        grade, label = "D", "High Risk"
    elif score >= 50:
        grade, label = "C", "Medium Risk"
    elif score >= 25:
        grade, label = "B", "Low Risk"
    else:
        grade, label = "A", "Minimal Risk"

    return {
        "score": score,
        "grade": grade,
        "label": label,
        "total_findings": len(findings),

        "breakdown": severity_count,

        "summary": f"{label} ({grade}) — {len(findings)} issues detected",

        "logic": {
            "cvss_weighted": True,
            "confidence_aware": True,
            "severity_normalized": True
        }
    }
