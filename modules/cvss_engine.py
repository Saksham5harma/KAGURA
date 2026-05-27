def calculate_cvss(severity, endpoint_type=None,
                   port_count=0):
    base = {
        "CRITICAL": 9.5,
        "HIGH":     7.5,
        "MEDIUM":   5.0,
        "LOW":      2.5
    }.get((severity or "LOW").upper(), 2.0)

    modifier = 0.0

    type_modifiers = {
        "API":   0.5,
        "AUTH":  1.0,
        "LEAK":  1.5,
        "ADMIN": 1.2,
    }
    if endpoint_type:
        modifier += type_modifiers.get(
            endpoint_type.upper(), 0.0)

    if port_count > 5:
        modifier += 0.5
    elif port_count > 10:
        modifier += 1.0

    return round(min(10.0, base + modifier), 1)
