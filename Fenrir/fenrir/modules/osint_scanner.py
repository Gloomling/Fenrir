# fenrir/modules/osint_scanner.py
import asyncio
import re
import httpx
from bs4 import BeautifulSoup
from ..logging_config import log

class OsintScanner:
    """
    Performs OSINT gathering by searching public sources for information.
    """
    def __init__(self):
        log.debug("OSINT Scanner module initialized.")
        # Regex to find email addresses
        self.email_regex = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
        # Common filetypes for document searches
        self.filetypes = ["pdf", "docx", "xlsx", "pptx", "txt", "csv"]

    async def search_public_sources(self, client: httpx.AsyncClient, query: str) -> set[str]:
        """
        Performs a search on DuckDuckGo and returns the text content of the results page.
        """
        search_url = "https://html.duckduckgo.com/html/"
        params = {"q": query}
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        try:
            response = await client.get(search_url, params=params, headers=headers, follow_redirects=True)
            if response.status_code == 200:
                return response.text
        except httpx.RequestError as e:
            log.error(f"Error during web search for query '{query}': {e}")
        return ""

    async def find_emails(self, client: httpx.AsyncClient, target_domain: str):
        """Searches for email addresses associated with the domain."""
        log.info(f"Searching for email addresses @{target_domain}...")
        query = f'"@{target_domain}"'
        page_content = await self.search_public_sources(client, query)
        
        if page_content:
            found_emails = set(self.email_regex.findall(page_content))
            # Filter for emails that actually belong to the target domain
            domain_emails = {email for email in found_emails if email.endswith(f"@{target_domain}")}
            
            if domain_emails:
                log.warning(f"Found {len(domain_emails)} potential email address(es):")
                for email in sorted(domain_emails):
                    log.warning(f"  - {email}")
            else:
                log.info("No publicly exposed email addresses found.")

    async def find_documents(self, client: httpx.AsyncClient, target_domain: str):
        """Searches for exposed documents related to the domain."""
        log.info("Searching for exposed documents...")
        filetype_query = " OR ".join([f"filetype:{ft}" for ft in self.filetypes])
        query = f"site:{target_domain} ({filetype_query})"
        page_content = await self.search_public_sources(client, query)

        if page_content:
            soup = BeautifulSoup(page_content, 'html.parser')
            links = {a['href'] for a in soup.find_all('a', href=True)}
            
            document_links = set()
            for link in links:
                if any(f".{ft}" in link for ft in self.filetypes) and target_domain in link:
                    document_links.add(link)
            
            if document_links:
                log.warning(f"Found {len(document_links)} potential exposed document(s):")
                for doc in sorted(document_links):
                    log.warning(f"  - {doc}")
            else:
                log.info("No publicly exposed documents found.")

    async def run(self, target_domain: str):
        """
        Runs the OSINT scan for the target domain.
        """
        log.info(f"Starting OSINT scan for {target_domain}...")
        
        async with httpx.AsyncClient() as client:
            await asyncio.gather(
                self.find_emails(client, target_domain),
                self.find_documents(client, target_domain)
            )
        
        log.info("OSINT scan finished.")
