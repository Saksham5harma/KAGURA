from engines.discovery_engine import DiscoveryEngine

engine = DiscoveryEngine()

results = engine.find_endpoints(
    "google.com"
)

for item in results:
    print(item)
