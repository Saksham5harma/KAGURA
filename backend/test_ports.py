from engines.port_scan import PortScanner

scanner = PortScanner()

results = scanner.scan(
    "google.com"
)

for item in results:
    print(item)
