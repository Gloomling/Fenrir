# File: fenrir/modules/iot_scanner.py
import asyncio
import json
from bleak import BleakScanner
from paho.mqtt.client import Client as MqttClient, MQTTv5
from ..logging_config import log

class IotScanner:
    """Scans for common IoT protocols like MQTT and Bluetooth LE."""
    def __init__(self):
        log.debug("IoT Scanner module initialized.")

    async def scan_ble_devices(self):
        """Scans for Bluetooth Low Energy (BLE) devices."""
        log.info("Starting BLE device scan for 10 seconds...")
        try:
            devices = await BleakScanner.discover(timeout=10.0)
            if devices:
                log.info(f"Found {len(devices)} BLE device(s):")
                for dev in devices:
                    log.info(f"  - {dev.address} - {dev.name or 'Unknown'}")
            else:
                log.info("No BLE devices found in the vicinity.")
        except Exception as e:
            log.error(f"Failed to scan for BLE devices. Ensure Bluetooth is enabled. Error: {e}")

    async def check_mqtt_anonymous_login(self, target_ip: str, port: int):
        """Checks if an MQTT broker allows anonymous login."""
        log.info(f"Checking for anonymous MQTT login on {target_ip}:{port}...")
        try:
            connected = asyncio.Event()
            
            def on_connect(client, userdata, flags, rc, properties):
                if rc == 0:
                    log.warning(f"SUCCESS: Anonymous login accepted on MQTT broker at {target_ip}:{port}")
                    client.disconnect()
                else:
                    log.info(f"Anonymous MQTT login failed with code: {rc}")
                connected.set()

            client = MqttClient(protocol=MQTTv5)
            client.on_connect = on_connect
            client.connect(target_ip, port, 60)
            client.loop_start()
            await asyncio.wait_for(connected.wait(), timeout=10)
            client.loop_stop(force=True)
        except Exception as e:
            log.info(f"Could not connect to MQTT broker at {target_ip}:{port}. Error: {e}")

    async def run(self, target_ip: str, open_ports: list[int]):
        """Runs the IoT scan."""
        log.info(f"Starting IoT scan on {target_ip}...")
        tasks = []
        # Check for MQTT on common ports
        mqtt_ports = [p for p in open_ports if p in [1883, 8883]]
        for port in mqtt_ports:
            tasks.append(self.check_mqtt_anonymous_login(target_ip, port))
        
        # Run BLE scan (not target-specific)
        tasks.append(self.scan_ble_devices())
        
        await asyncio.gather(*tasks)
        log.info("IoT scan finished.")
```python
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
# File: fenrir/modules/mobile_scanner.py
import os
import zipfile
import hashlib
from androguard.core.bytecodes.apk import APK
from ..logging_config import log

class MobileScanner:
    """Performs static analysis on mobile application files (APKs)."""
    def __init__(self):
        log.debug("Mobile Scanner module initialized.")

    def analyze_apk(self, file_path: str):
        """Analyzes a single Android APK file."""
        try:
            log.info(f"Analyzing APK: {os.path.basename(file_path)}")
            a = APK(file_path)
            
            if not a.is_valid_apk():
                log.error("Invalid APK file provided.")
                return

            log.info("Basic APK Information:")
            log.info(f"  - Package Name: {a.get_package()}")
            log.info(f"  - Main Activity: {a.get_main_activity()}")
            log.info(f"  - App Name: {a.get_app_name()}")
            
            permissions = a.get_permissions()
            log.info(f"Found {len(permissions)} permission(s):")
            # Check for potentially dangerous permissions
            dangerous_perms = [
                "android.permission.READ_SMS", "android.permission.SEND_SMS",
                "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
                "android.permission.ACCESS_FINE_LOCATION", "android.permission.RECORD_AUDIO"
            ]
            for perm in sorted(permissions):
                if any(dp in perm for dp in dangerous_perms):
                    log.warning(f"  - {perm} (Potentially Dangerous)")
                else:
                    log.info(f"  - {perm}")

        except Exception as e:
            log.error(f"Failed to analyze APK {file_path}. Is it a valid file? Error: {e}")

    async def run(self, file_path: str):
        """Runs the mobile application scan."""
        log.info(f"Starting mobile application scan on {file_path}...")
        
        if not os.path.exists(file_path):
            log.error(f"File not found: {file_path}")
            return

        if file_path.lower().endswith(".apk"):
            # Run synchronous analysis in a thread
            await asyncio.to_thread(self.analyze_apk, file_path)
        else:
            log.error("Unsupported file type. This module currently only supports .apk files.")
            
        log.info("Mobile application scan finished.")
```python
# File: fenrir/modules/rf_scanner.py
import asyncio
from ..logging_config import log

class RfScanner:
    """
    Simulates scanning for common RF signals.
    NOTE: Real RF scanning requires specific hardware (SDR) and complex libraries.
          This is a placeholder demonstrating the tool's structure.
    """
    def __init__(self):
        log.debug("RF Scanner module initialized.")

    async def run(self, duration: int = 20):
        """Runs the RF scan simulation."""
        log.info(f"Starting RF scan simulation for {duration} seconds...")
        log.warning("This is a SIMULATION. Real RF scanning requires an SDR and is not implemented.")
        
        # --- Placeholder Logic ---
        # A real implementation would:
        # 1. Initialize an SDR device (e.g., using pyrtlsdr or SoapySDR).
        # 2. Scan a range of frequencies (e.g., 300-900 MHz for common devices).
        # 3. Analyze the power spectrum to find signals.
        # 4. Attempt to demodulate and decode found signals.
        
        log.info("Scanning common frequencies (433MHz, 915MHz, 2.4GHz)...")
        await asyncio.sleep(duration / 2)
        
        log.info("RF scan simulation complete.")
        log.info("Found the following signals (simulation):")
        log.warning("  - 433.92 MHz: Strong ASK/OOK signal detected (likely a remote control or sensor).")
        log.info("  - 2.45 GHz: Wideband signal detected (likely Wi-Fi or Bluetooth).")
        
        log.info("RF scan finished.")
