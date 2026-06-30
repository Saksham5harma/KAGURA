from engines.port_engine import scan_ports

async def _run_port_scan(self, target, discovery_data):
    return await scan_ports(target)
