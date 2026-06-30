class CVSSEngine:

    def calculate(self, vuln):

        severity = vuln.get("severity", "Info")

        mapping = {
            "Critical": 9.8,
            "High": 8.0,
            "Medium": 5.5,
            "Low": 3.1,
            "Info": 0.0
        }

        return mapping.get(severity, 0.0)
