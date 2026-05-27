from discovery.endpoints import discover_endpoints

def bus(event, data):

    print(f"[{event}] {data}")

results = discover_endpoints(
    "example.com",
    bus
)

print("\nTOTAL ENDPOINTS:", len(results))
