# fenrir/database/__init__.py
#
# Package initialiser for the Fenrir offline intelligence database.
#
# Exports the two primary interfaces:
#   DatabaseManager — query interface used by scanner modules
#   DatabaseBuilder — build and update interface used by CLI/GUI
#
# Usage:
#   from fenrir.database import DatabaseManager, DatabaseBuilder
#   from fenrir.database import get_db_manager  # singleton accessor

from .db_manager import DatabaseManager
from .db_builder import DatabaseBuilder

# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------
# A single DatabaseManager instance is shared across all scanner modules
# to avoid opening multiple SQLite connections unnecessarily.

_db_manager_instance: DatabaseManager | None = None


def get_db_manager() -> DatabaseManager:
    """
    Return the shared DatabaseManager singleton.

    Initialises the instance on first call. Subsequent calls return the
    same instance. Thread-safe for reads; DatabaseManager uses a
    threading.Lock for write operations.

    Returns:
        DatabaseManager instance pointed at the default database path.
    """
    global _db_manager_instance
    if _db_manager_instance is None:
        _db_manager_instance = DatabaseManager()
    return _db_manager_instance


__all__ = [
    "DatabaseManager",
    "DatabaseBuilder",
    "get_db_manager",
]
