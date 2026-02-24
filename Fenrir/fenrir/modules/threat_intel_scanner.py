# fenrir/modules/threat_intel_scanner.py
import httpx
from ..logging_config import log
from ..config import config

class ThreatIntelScanner:
    """
    Queries threat intelligence sources for information about a target IP or domain.
    """
    def __init__(self):
        log.debug("Threat Intelligence Scanner module initialized.")
        self.vt_api_key = config.VIRUSTOTAL_API_KEY
        self.vt_base_url = "https://www.virustotal.com/api/v3/ip_addresses/"

    async def run(self, target_ip: str):
        """
        Runs the threat intelligence scan.
        """
        log.info(f"Starting threat intelligence scan for {target_ip}...")

        if not self.vt_api_key or self.vt_api_key == "YOUR_VIRUSTOTAL_API_KEY_HERE":
            log.warning("VirusTotal API key not configured in .env file. Skipping VirusTotal scan.")
            return

        await self.query_virustotal(target_ip)
        
        log.info("Threat intelligence scan finished.")

    async def query_virustotal(self, target_ip: str):
        """
        Queries the VirusTotal API for IP address reputation.
        """
        log.info(f"Querying VirusTotal for {target_ip}...")
        headers = {"x-apikey": self.vt_api_key}
        url = f"{self.vt_base_url}{target_ip}"

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(url, headers=headers)

            if response.status_code == 200:
                data = response.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                
                log.info("VirusTotal Reputation:")
                log.info(f"  - Malicious Detections: {malicious}")
                log.info(f"  - Suspicious Detections: {suspicious}")
                
                if malicious > 0 or suspicious > 0:
                    log.warning(f"Target {target_ip} is flagged by VirusTotal.")
                else:
                    log.info(f"Target {target_ip} appears clean according to VirusTotal.")
            
            elif response.status_code == 404:
                log.info(f"Target {target_ip} not found in VirusTotal database.")
            else:
                log.error(f"VirusTotal API error. Status: {response.status_code}, Response: {response.text}")

        except httpx.RequestError as e:
            log.error(f"Could not connect to VirusTotal API: {e}")
        except Exception as e:
            log.error(f"An unexpected error occurred during VirusTotal scan: {e}")

