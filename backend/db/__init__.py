"""
Windows Forensic Toolkit (WFT) DFIR Suite - Database Package
"""
from backend.db.schema import (
    CORE_TABLES,
    CORE_SCHEMA_SQL,
    init_schema,
    verify_core_tables,
    sync_artifact_registry_counts,
)
from backend.db.engine import (
    DuckDBManager,
    init_case_db,
    query_paginated,
    get_table_columns,
    log_processing_event,
)

__all__ = [
    "CORE_TABLES",
    "CORE_SCHEMA_SQL",
    "init_schema",
    "verify_core_tables",
    "sync_artifact_registry_counts",
    "DuckDBManager",
    "init_case_db",
    "query_paginated",
    "get_table_columns",
    "log_processing_event",
]
