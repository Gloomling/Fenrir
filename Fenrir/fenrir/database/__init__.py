# fenrir/database/__init__.py
#
# Package initialiser for the Fenrir offline intelligence database.
#
# Exports the two primary interfaces:
#   DatabaseManager — query interface used by scanner modules
#   DatabaseBuilder — build and update interface used by CLI/GUI
#
# DatabaseBuilder is imported lazily (inside get_db_builder / CLI calls)
# to avoid pulling in heavy build-time dependencies (PyYAML, GitPython, etc.)
# when scanner modules only need DatabaseManager for queries.

from .db_manager import DatabaseManager

# ---------------------------------------------------------------------------
# Singleton accessor — scanner modules use this
# ---------------------------------------------------------------------------

_db_manager_instance: DatabaseManager | None = None


def get_db_manager() -> DatabaseManager:
    """
    Return the shared DatabaseManager singleton.
    Initialises on first call; subsequent calls return the same instance.
    """
    global _db_manager_instance
    if _db_manager_instance is None:
        _db_manager_instance = DatabaseManager()
    return _db_manager_instance


def get_db_builder():
    """
    Lazily import and return the DatabaseBuilder class.
    Import is deferred so scanner modules don't pay the cost of loading
    PyYAML, GitPython, and other build-only dependencies on startup.

    Usage:
        from fenrir.database import get_db_builder
        DatabaseBuilder = get_db_builder()
        builder = DatabaseBuilder()
    """
    from .db_builder import DatabaseBuilder
    return DatabaseBuilder


__all__ = [
    "DatabaseManager",
    "get_db_manager",
    "get_db_builder",
]