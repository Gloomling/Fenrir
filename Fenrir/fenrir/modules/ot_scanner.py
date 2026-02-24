# File: fenrir/modules/ot_scanner.py
import asyncio
from scapy.all import sniff, TCP
from ..logging_config import log

class OtScanner:
    """Performs passive scanning for common Operational Technology (OT) protocols."""
    def __init__(self):
        log.debug("OT Scanner module initialized.")
        self.detected_devices = {}

    def packet_handler(self, pkt):
        """Packet handler for Scapy to identify OT protocols."""
        if pkt.haslayer(TCP):
            src_ip, dst_ip = pkt[1].src, pkt[1].dst
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
            
            # Modbus TCP default port
            if dport == 502 or sport == 502:
                if src_ip not in self.detected_devices:
                    log.warning(f"Detected potential Modbus traffic from {src_ip}:{sport} to {dst_ip}:{dport}")
                    self.detected_devices[src_ip] = "Modbus"

            # Siemens S7 default port
            if dport == 102 or sport == 102:
                if src_ip not in self.detected_devices:
                    log.warning(f"Detected potential Siemens S7 traffic from {src_ip}:{sport} to {dst_ip}:{dport}")
                    self.detected_devices[src_ip] = "Siemens S7"

    async def run(self, duration: int = 30):
        """Runs the passive OT scan."""
        log.info(f"Starting passive OT network scan for {duration} seconds...")
        log.info("Listening for Modbus (port 502) and Siemens S7 (port 102) traffic...")
        log.warning("This requires root privileges to run.")
        
        try:
            # Run the synchronous sniff function in a separate thread
            await asyncio.to_thread(
                sniff,
                prn=self.packet_handler,
                filter="tcp",
                store=0,
                timeout=duration
            )
            
            if not self.detected_devices:
                log.info("No common OT protocol traffic detected during the scan.")

        except Exception as e:
            log.error(f"An error occurred during the passive OT scan. Do you have root privileges? Error: {e}")
        
        log.info("Passive OT scan finished.")
```python
