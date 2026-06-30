from datetime import datetime

class EvidenceBuilder:

    def build(self, vuln, target):

        return {
            "target": target,
            "finding": vuln["title"],
            "timestamp": datetime.utcnow().isoformat()
        }
