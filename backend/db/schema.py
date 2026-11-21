"""
Windows Forensic Toolkit (WFT) DFIR Suite - DuckDB Schema Definitions & Master Artifact Catalog
Categorized into WFT's exact 10 canonical categories with granular
per-application, per-artifact tables and views, plus dynamic per-.evtx views under EVENT LOGS.
"""
import re
from typing import Any, Dict, List, Optional, Tuple
import duckdb

CANONICAL_CATEGORIES: List[str] = [
    "REFINED RESULTS",
    "WEB RELATED",
    "CHAT",
    "EMAIL & CALENDAR",
    "CLOUD",
    "MEDIA",
    "DOCUMENTS",
    "EVENT LOGS",
    "OPERATING SYSTEM",
    "MALWARE & YARA",
]
CANONICAL_WFT_CATEGORIES = CANONICAL_CATEGORIES

CATEGORY_NORMALIZATION_MAP: Dict[str, str] = {
    "REFINED RESULTS": "REFINED RESULTS",
    "KEYWORD HITS": "REFINED RESULTS",
    "WEB RELATED": "WEB RELATED",
    "WEB BROWSERS": "WEB RELATED",
    "CHAT": "CHAT",
    "CHAT & COLLABORATION": "CHAT",
    "EMAIL": "EMAIL & CALENDAR",
    "EMAILS": "EMAIL & CALENDAR",
    "MAIL": "EMAIL & CALENDAR",
    "EMAIL & CALENDAR": "EMAIL & CALENDAR",
    "CLOUD": "CLOUD",
    "CLOUD STORAGE": "CLOUD",
    "MEDIA": "MEDIA",
    "MEDIA & PICTURES": "MEDIA",
    "MEDIA & OCR": "MEDIA",
    "DOCUMENTS": "DOCUMENTS",
    "DOCUMENTS & METADATA": "DOCUMENTS",
    "EVENT LOGS": "EVENT LOGS",
    "OPERATING SYSTEM": "OPERATING SYSTEM",
    "PROGRAM EXECUTION": "OPERATING SYSTEM",
    "FILE SYSTEM": "OPERATING SYSTEM",
    "REGISTRY & OS": "OPERATING SYSTEM",
    "NETWORK & SRUM": "OPERATING SYSTEM",
    "USB & EXTERNAL DEVICES": "OPERATING SYSTEM",
    "DATABASE & SQLITE": "OPERATING SYSTEM",
    "MALWARE & YARA": "MALWARE & YARA",
    "MALWARE & THREAT HUNTING": "MALWARE & YARA",
}

CORE_TABLES: List[str] = [
    "artifact_registry",
    "master_timeline",
    "entity_connections",
    "file_enrichment",
    "artifact_yara_hits",
    "artifact_ocr_results",
    "bookmarks",
    "processing_logs",
    "case_keywords",
    "case_metadata",
    "raw_regripper",
    "artifact_stinger_hits",
    "parsed_media_exif",
    "parsed_documents_metadata",
]

CORE_SCHEMA_SQL: str = """
-- 0. Case Metadata Key-Value Store
CREATE TABLE IF NOT EXISTS case_metadata (
    key VARCHAR PRIMARY KEY,
    value VARCHAR,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 1. Tracks every populated artifact table so the UI Left Sidebar builds dynamically
CREATE TABLE IF NOT EXISTS artifact_registry (
    artifact_id VARCHAR PRIMARY KEY,
    category VARCHAR NOT NULL,
    display_name VARCHAR NOT NULL,
    table_name VARCHAR NOT NULL,
    source_tool VARCHAR NOT NULL,
    row_count BIGINT DEFAULT 0,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. Unified Chronological Super-Timeline (Unpivoted from all artifact timestamp columns)
CREATE TABLE IF NOT EXISTS master_timeline (
    timeline_id BIGINT,
    timestamp_utc TIMESTAMP NOT NULL,
    timestamp_type VARCHAR NOT NULL,
    category VARCHAR NOT NULL,
    artifact_name VARCHAR NOT NULL,
    primary_entity VARCHAR,
    secondary_entity VARCHAR,
    summary VARCHAR,
    source_table VARCHAR NOT NULL,
    source_row_id BIGINT NOT NULL,
    source_file VARCHAR,
    macb VARCHAR DEFAULT ''
);

-- 3. WFT "Connections" Entity Graph Table
CREATE TABLE IF NOT EXISTS entity_connections (
    connection_id BIGINT,
    entity_type VARCHAR NOT NULL,
    entity_value VARCHAR NOT NULL,
    category VARCHAR NOT NULL,
    artifact_name VARCHAR NOT NULL,
    source_table VARCHAR NOT NULL,
    source_row_id BIGINT NOT NULL,
    context_label VARCHAR,
    timestamp_utc TIMESTAMP
);

-- 4. File Enrichment & Malware/OCR Table
CREATE TABLE IF NOT EXISTS file_enrichment (
    _row_id BIGINT,
    enrichment_id BIGINT,
    file_path VARCHAR NOT NULL,
    file_name VARCHAR NOT NULL,
    extension VARCHAR,
    size_bytes BIGINT,
    md5 VARCHAR,
    sha256 VARCHAR,
    shannon_entropy DOUBLE,
    is_pe BOOLEAN DEFAULT FALSE,
    pe_imphash VARCHAR,
    pe_compile_time TIMESTAMP,
    pe_sections_info VARCHAR,
    is_high_entropy BOOLEAN DEFAULT FALSE,
    yara_hit_count INTEGER DEFAULT 0,
    ioc_hit_count INTEGER DEFAULT 0,
    yara_rules_matched VARCHAR,
    yara_match_offsets VARCHAR,
    ocr_extracted_text VARCHAR,
    archive_parent VARCHAR,
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 5. Examiner Bookmarks, Tags & Notes
CREATE TABLE IF NOT EXISTS bookmarks (
    bookmark_id VARCHAR PRIMARY KEY,
    source_table VARCHAR NOT NULL,
    source_row_id BIGINT NOT NULL,
    tag_name VARCHAR NOT NULL,
    examiner_notes VARCHAR,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 6. Processing Job Audit Log
CREATE TABLE IF NOT EXISTS processing_logs (
    log_id BIGINT,
    timestamp_utc TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    module_name VARCHAR,
    command_executed VARCHAR,
    exit_code INTEGER,
    rows_ingested BIGINT,
    duration_ms BIGINT,
    status VARCHAR,
    error_message VARCHAR
);

-- 7. YARA-X Malware Rule Hits Table
CREATE TABLE IF NOT EXISTS artifact_yara_hits (
    _row_id BIGINT,
    file_path VARCHAR NOT NULL,
    file_name VARCHAR NOT NULL,
    extension VARCHAR,
    size_bytes BIGINT,
    sha256 VARCHAR,
    rule_name VARCHAR NOT NULL,
    rule_namespace VARCHAR,
    pattern_identifier VARCHAR,
    match_offset BIGINT,
    match_length BIGINT,
    match_data_hex VARCHAR,
    severity VARCHAR,
    category VARCHAR,
    description VARCHAR,
    mitre_attack VARCHAR,
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 8. RapidOCR Extracted Text Tables
CREATE TABLE IF NOT EXISTS artifact_ocr_results (
    _row_id BIGINT,
    file_path VARCHAR,
    file_name VARCHAR,
    dimensions VARCHAR,
    sha256 VARCHAR,
    extracted_text VARCHAR,
    ocr_text VARCHAR,
    confidence DOUBLE,
    avg_confidence DOUBLE,
    engine VARCHAR,
    line_count INTEGER,
    char_count INTEGER,
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source_file VARCHAR
);

CREATE TABLE IF NOT EXISTS media_ocr_results (
    _row_id BIGINT,
    file_path VARCHAR,
    file_name VARCHAR,
    dimensions VARCHAR,
    sha256 VARCHAR,
    extracted_text VARCHAR,
    ocr_text VARCHAR,
    confidence DOUBLE,
    avg_confidence DOUBLE,
    engine VARCHAR,
    line_count INTEGER,
    char_count INTEGER,
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source_file VARCHAR
);

-- 9. Case Keyword Search Tables
CREATE TABLE IF NOT EXISTS case_keywords (
    keyword_id VARCHAR PRIMARY KEY,
    keyword VARCHAR UNIQUE NOT NULL,
    is_regex BOOLEAN DEFAULT FALSE,
    is_case_sensitive BOOLEAN DEFAULT FALSE,
    case_sensitive BOOLEAN DEFAULT FALSE,
    category VARCHAR DEFAULT 'General',
    source_file VARCHAR,
    hit_count BIGINT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS parsed_keyword_hits (
    _row_id BIGINT,
    keyword_id VARCHAR,
    keyword VARCHAR,
    is_regex BOOLEAN DEFAULT FALSE,
    is_case_sensitive BOOLEAN DEFAULT FALSE,
    artifact_name VARCHAR,
    source_table VARCHAR,
    source_row_id BIGINT,
    matched_column VARCHAR,
    match_offset BIGINT,
    encoding VARCHAR,
    matched_snippet VARCHAR,
    source_file VARCHAR,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 10. RegRipper Parsed Plugins Table
CREATE TABLE IF NOT EXISTS raw_regripper (
    _row_id BIGINT,
    plugin_name VARCHAR NOT NULL,
    plugin_version VARCHAR,
    hive_name VARCHAR NOT NULL,
    hive_type VARCHAR NOT NULL,
    category VARCHAR,
    mitre_attack VARCHAR,
    description VARCHAR,
    report_text VARCHAR NOT NULL,
    summary_line VARCHAR,
    output_lines_count INTEGER,
    parsed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 11. Trellix Stinger & PE Threat Detections Table
CREATE TABLE IF NOT EXISTS artifact_stinger_hits (
    _row_id BIGINT,
    file_path VARCHAR NOT NULL,
    file_name VARCHAR NOT NULL,
    sha256 VARCHAR,
    malware_name VARCHAR,
    detection_type VARCHAR,
    action_taken VARCHAR,
    engine VARCHAR DEFAULT 'Trellix Stinger',
    engine_version VARCHAR,
    details VARCHAR,
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 12. Parsed Media EXIF Metadata Table (Internal storage for granular views)
CREATE TABLE IF NOT EXISTS parsed_media_exif (
    _row_id BIGINT, file_path VARCHAR, file_name VARCHAR, file_type VARCHAR, file_size_bytes BIGINT, sha256 VARCHAR, camera_make VARCHAR, camera_model VARCHAR, datetime_original TIMESTAMP, software VARCHAR, image_width INTEGER, image_height INTEGER, duration_seconds DOUBLE, latitude DOUBLE, longitude DOUBLE, gps_position VARCHAR, gps_coordinates VARCHAR, raw_metadata VARCHAR, source_file VARCHAR
);

-- 13. Parsed Documents & Zone.Identifier Metadata Tables
CREATE TABLE IF NOT EXISTS parsed_documents_metadata (
    _row_id BIGINT, file_path VARCHAR, file_name VARCHAR, file_type VARCHAR, file_size_bytes BIGINT, title VARCHAR, author VARCHAR, last_modified_by VARCHAR, created_time TIMESTAMP, modified_time TIMESTAMP, page_count INTEGER, word_count INTEGER, has_macros BOOLEAN, embedded_links VARCHAR, zone_id INTEGER, zone_host_url VARCHAR, zone_referrer_url VARCHAR, host_url VARCHAR, referrer_url VARCHAR, sha256 VARCHAR, source_file VARCHAR
);

CREATE TABLE IF NOT EXISTS parsed_text_documents (
    _row_id BIGINT, file_path VARCHAR, file_name VARCHAR, file_type VARCHAR, extension VARCHAR, file_size_bytes BIGINT,
    created_time TIMESTAMP, modified_time TIMESTAMP, author VARCHAR, title VARCHAR, last_modified_by VARCHAR,
    encoding VARCHAR, line_count INTEGER, word_count INTEGER, char_count BIGINT,
    content_preview VARCHAR, text_preview VARCHAR, embedded_links VARCHAR,
    zone_id INTEGER, zone_host_url VARCHAR, zone_referrer_url VARCHAR, host_url VARCHAR, referrer_url VARCHAR,
    sha256 VARCHAR, source_file VARCHAR
);

-- 14. Virtual File System & Volume Shadow Copy Metadata Tables
CREATE TABLE IF NOT EXISTS vfs_partitions (
    _row_id BIGINT,
    part_index INTEGER,
    partition_index INTEGER,
    addr BIGINT,
    label VARCHAR,
    volume_label VARCHAR,
    description VARCHAR,
    fs_type VARCHAR,
    start_sector BIGINT,
    offset_bytes BIGINT,
    start_offset_bytes BIGINT,
    length_sectors BIGINT,
    size_bytes BIGINT,
    volume_serial VARCHAR,
    serial_number VARCHAR,
    is_boot BOOLEAN,
    is_bootable BOOLEAN,
    flags VARCHAR
);

CREATE TABLE IF NOT EXISTS vfs_files (
    _row_id BIGINT,
    part_index INTEGER,
    partition_index INTEGER,
    fs_type VARCHAR,
    inode BIGINT,
    parent_inode BIGINT,
    vfs_path VARCHAR,
    staged_rel_path VARCHAR,
    file_name VARCHAR,
    extension VARCHAR,
    parent_path VARCHAR,
    size_bytes BIGINT,
    is_dir BOOLEAN,
    is_directory BOOLEAN,
    is_allocated BOOLEAN,
    is_deleted BOOLEAN,
    si_created TIMESTAMP,
    si_modified TIMESTAMP,
    si_accessed TIMESTAMP,
    si_changed TIMESTAMP,
    fn_created TIMESTAMP,
    fn_modified TIMESTAMP,
    fn_accessed TIMESTAMP,
    fn_changed TIMESTAMP,
    si_created_utc TIMESTAMP,
    si_modified_utc TIMESTAMP,
    si_accessed_utc TIMESTAMP,
    si_changed_utc TIMESTAMP,
    fn_created_utc TIMESTAMP,
    fn_modified_utc TIMESTAMP,
    fn_accessed_utc TIMESTAMP,
    fn_changed_utc TIMESTAMP,
    mft_entry BIGINT,
    vss_store_index INTEGER
);

CREATE TABLE IF NOT EXISTS vfs_shadow_copies (
    _row_id BIGINT,
    vss_index INTEGER,
    store_index INTEGER,
    part_index INTEGER,
    partition_index INTEGER,
    store_id VARCHAR,
    vss_id VARCHAR,
    volume_label VARCHAR,
    shadow_copy_guid VARCHAR,
    volume_guid VARCHAR,
    creation_time TIMESTAMP,
    creation_time_utc TIMESTAMP,
    size_bytes BIGINT,
    shadow_copy_size BIGINT,
    store_size_bytes BIGINT,
    attribute_flags BIGINT,
    machine_name VARCHAR,
    originating_machine VARCHAR,
    servicing_machine VARCHAR,
    staged_prefix VARCHAR,
    files_staged INTEGER,
    status VARCHAR
);

-- 15. Internal Combined Browser & Notification Staging Tables (for multi-source parser compatibility)
CREATE TABLE IF NOT EXISTS parsed_browser_history (
    _row_id BIGINT,
    browser VARCHAR,
    profile VARCHAR,
    url VARCHAR,
    title VARCHAR,
    visit_time TIMESTAMP,
    visit_time_utc TIMESTAMP,
    visit_count BIGINT,
    typed_count BIGINT,
    visit_source VARCHAR,
    source_path VARCHAR,
    source_file VARCHAR
);

CREATE TABLE IF NOT EXISTS parsed_browser_downloads (
    _row_id BIGINT,
    browser VARCHAR,
    profile VARCHAR,
    url VARCHAR,
    site_url VARCHAR,
    tab_url VARCHAR,
    target_path VARCHAR,
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    start_time_utc TIMESTAMP,
    end_time_utc TIMESTAMP,
    received_bytes BIGINT,
    total_bytes BIGINT,
    mime_type VARCHAR,
    state VARCHAR,
    danger_type VARCHAR,
    source_path VARCHAR,
    source_file VARCHAR
);

CREATE TABLE IF NOT EXISTS parsed_browser_logins (
    _row_id BIGINT,
    browser VARCHAR,
    profile VARCHAR,
    origin_url VARCHAR,
    action_url VARCHAR,
    username_value VARCHAR,
    password_present BOOLEAN,
    date_created TIMESTAMP,
    date_last_used TIMESTAMP,
    date_created_utc TIMESTAMP,
    date_last_used_utc TIMESTAMP,
    times_used BIGINT,
    source_path VARCHAR,
    source_file VARCHAR
);

CREATE TABLE IF NOT EXISTS parsed_notifications (
    _row_id BIGINT,
    notification_id BIGINT,
    app_id VARCHAR,
    notification_type VARCHAR,
    payload VARCHAR,
    arrival_time TIMESTAMP,
    expiry_time TIMESTAMP,
    timestamp_utc TIMESTAMP,
    title VARCHAR,
    body VARCHAR,
    header VARCHAR,
    action_url VARCHAR,
    source_path VARCHAR,
    source_file VARCHAR
);

-- Auto-incrementing helper sequences
CREATE SEQUENCE IF NOT EXISTS seq_timeline_id START 1;
CREATE SEQUENCE IF NOT EXISTS seq_connection_id START 1;
CREATE SEQUENCE IF NOT EXISTS seq_enrichment_id START 1;
CREATE SEQUENCE IF NOT EXISTS seq_yara_id START 1;
CREATE SEQUENCE IF NOT EXISTS seq_ocr_id START 1;
CREATE SEQUENCE IF NOT EXISTS seq_stinger_id START 1;
CREATE SEQUENCE IF NOT EXISTS seq_log_id START 1;

-- Targeted Indexes for Super-Timeline & Entity Graph Queries
CREATE INDEX IF NOT EXISTS idx_mt_timestamp ON master_timeline(timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_mt_category ON master_timeline(category);
CREATE INDEX IF NOT EXISTS idx_mt_source_table ON master_timeline(source_table);
CREATE INDEX IF NOT EXISTS idx_ec_entity_val ON entity_connections(entity_value);
CREATE INDEX IF NOT EXISTS idx_ec_source_table ON entity_connections(source_table);
"""

# =============================================================================
# PERMANENT MASTER ARTIFACT CATALOG
# Across all 10 Canonical WFT Categories
# =============================================================================
MASTER_ARTIFACT_CATALOG: List[Dict[str, Any]] = [
    # -------------------------------------------------------------------------
    # 1. REFINED RESULTS
    # -------------------------------------------------------------------------
    {
        "artifact_id": "keyword_hits",
        "category": "REFINED RESULTS",
        "display_name": "Keyword Hits",
        "table_name": "view_keyword_hits",
        "source_tool": "KeywordScanner",
        "ddl": """CREATE OR REPLACE VIEW view_keyword_hits AS
            SELECT
                _row_id, keyword_id, keyword, is_regex, is_case_sensitive,
                artifact_name, source_table, source_row_id,
                matched_column, match_offset, encoding,
                matched_snippet, source_file, detected_at
            FROM parsed_keyword_hits
            ORDER BY _row_id ASC;"""
    },
    {
        "artifact_id": "refined_domains",
        "category": "REFINED RESULTS",
        "display_name": "Extracted URLs & Domains",
        "table_name": "view_refined_domains",
        "source_tool": "RefinedResults",
        "ddl": """CREATE OR REPLACE VIEW view_refined_domains AS
            SELECT
                row_number() OVER (ORDER BY occurrence_count DESC, indicator ASC) AS _row_id,
                indicator AS domain,
                indicator AS domain_or_url,
                indicator,
                entity_type,
                occurrence_count AS event_count,
                occurrence_count AS total_occurrences,
                occurrence_count,
                distinct_artifacts_count,
                first_seen_utc AS first_seen,
                first_seen_utc AS first_observed_utc,
                first_seen_utc,
                last_seen_utc AS last_seen,
                last_seen_utc AS last_observed_utc,
                last_seen_utc,
                sources AS observed_in_artifacts,
                sources
            FROM (
                SELECT
                    entity_value AS indicator,
                    UPPER(entity_type) AS entity_type,
                    COUNT(*) AS occurrence_count,
                    COUNT(DISTINCT artifact_name) AS distinct_artifacts_count,
                    MIN(timestamp_utc) AS first_seen_utc,
                    MAX(timestamp_utc) AS last_seen_utc,
                    STRING_AGG(DISTINCT artifact_name, ', ') AS sources
                FROM entity_connections
                WHERE UPPER(entity_type) IN ('DOMAIN', 'URL', 'IP', 'IP_ADDRESS', 'HOST')
                  AND COALESCE(TRIM(entity_value), '') != ''
                GROUP BY entity_value, UPPER(entity_type)
            ) sub_dom;"""
    },
    {
        "artifact_id": "refined_users",
        "category": "REFINED RESULTS",
        "display_name": "User Accounts & Identifiers",
        "table_name": "view_refined_users",
        "source_tool": "RefinedResults",
        "ddl": """CREATE OR REPLACE VIEW view_refined_users AS
            SELECT
                row_number() OVER (ORDER BY occurrence_count DESC, identity ASC) AS _row_id,
                identity AS user_identifier,
                identity,
                entity_type,
                sources AS source_artifact,
                occurrence_count AS total_occurrences,
                occurrence_count,
                first_seen_utc AS first_observed_utc,
                first_seen_utc,
                last_seen_utc AS last_observed_utc,
                last_seen_utc,
                sources AS observed_in_artifacts,
                sources
            FROM (
                SELECT
                    entity_value AS identity,
                    UPPER(entity_type) AS entity_type,
                    COUNT(*) AS occurrence_count,
                    MIN(timestamp_utc) AS first_seen_utc,
                    MAX(timestamp_utc) AS last_seen_utc,
                    STRING_AGG(DISTINCT artifact_name, ', ') AS sources
                FROM entity_connections
                WHERE UPPER(entity_type) IN ('USER_ACCOUNT', 'USER', 'USERNAME', 'ACCOUNT', 'EMAIL_ADDRESS', 'EMAIL', 'SID')
                  AND COALESCE(TRIM(entity_value), '') != ''
                GROUP BY entity_value, UPPER(entity_type)
            ) sub_usr;"""
    },
    {
        "artifact_id": "bulk_extractor_features",
        "category": "REFINED RESULTS",
        "display_name": "Bulk Extractor Features",
        "table_name": "parsed_bulk_extractor_features",
        "source_tool": "bulk_extractor",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_bulk_extractor_features (
            _row_id BIGINT, scanner VARCHAR, offset_str VARCHAR, feature VARCHAR, context VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "bulk_extractor_histograms",
        "category": "REFINED RESULTS",
        "display_name": "Bulk Extractor Histograms",
        "table_name": "parsed_bulk_extractor_histograms",
        "source_tool": "bulk_extractor",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_bulk_extractor_histograms (
            _row_id BIGINT, scanner VARCHAR, count BIGINT, feature VARCHAR, source_file VARCHAR
        );"""
    },
    # -------------------------------------------------------------------------
    # 2. WEB RELATED (Split per browser: Chrome, Edge, Brave, Firefox)
    # -------------------------------------------------------------------------
    # Chrome
    {
        "artifact_id": "chrome_autofill",
        "category": "WEB RELATED",
        "display_name": "Chrome Autofill",
        "table_name": "parsed_chrome_autofill",
        "source_tool": "ChromiumParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_chrome_autofill (
            _row_id BIGINT, name VARCHAR, value VARCHAR, value_lower VARCHAR, date_created TIMESTAMP, date_last_used TIMESTAMP, count INTEGER, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "chrome_bookmarks",
        "category": "WEB RELATED",
        "display_name": "Chrome Bookmarks",
        "table_name": "parsed_chrome_bookmarks",
        "source_tool": "ChromiumParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_chrome_bookmarks (
            _row_id BIGINT, title VARCHAR, url VARCHAR, date_added TIMESTAMP, date_modified TIMESTAMP, folder VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "chrome_cache",
        "category": "WEB RELATED",
        "display_name": "Chrome Cache Records",
        "table_name": "parsed_chrome_cache",
        "source_tool": "ChromiumParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_chrome_cache (
            _row_id BIGINT, url VARCHAR, key VARCHAR, response_time TIMESTAMP, content_type VARCHAR, size_bytes BIGINT, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "chrome_cookies",
        "category": "WEB RELATED",
        "display_name": "Chrome Cookies",
        "table_name": "parsed_chrome_cookies",
        "source_tool": "ChromiumParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_chrome_cookies (
            _row_id BIGINT, host_key VARCHAR, name VARCHAR, value VARCHAR, path VARCHAR, creation_utc TIMESTAMP, expires_utc TIMESTAMP, last_access_utc TIMESTAMP, is_secure BOOLEAN, is_httponly BOOLEAN, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "chrome_session",
        "category": "WEB RELATED",
        "display_name": "Chrome Current Session & Tabs",
        "table_name": "parsed_chrome_session",
        "source_tool": "ChromiumParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_chrome_session (
            _row_id BIGINT, browser VARCHAR, profile VARCHAR, window_id BIGINT, tab_id BIGINT, url VARCHAR, title VARCHAR, active BOOLEAN, last_active_time TIMESTAMP, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "chrome_downloads",
        "category": "WEB RELATED",
        "display_name": "Chrome Downloads",
        "table_name": "parsed_chrome_downloads",
        "source_tool": "ChromiumParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_chrome_downloads (
            _row_id BIGINT, browser VARCHAR, profile VARCHAR, target_path VARCHAR, tab_url VARCHAR, site_url VARCHAR, total_bytes BIGINT, received_bytes BIGINT, start_time TIMESTAMP, end_time TIMESTAMP, mime_type VARCHAR, danger_type VARCHAR, state VARCHAR, opened INTEGER, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "chrome_search_terms",
        "category": "WEB RELATED",
        "display_name": "Chrome Keyword Search Terms",
        "table_name": "parsed_chrome_search_terms",
        "source_tool": "ChromiumParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_chrome_search_terms (
            _row_id BIGINT, term VARCHAR, normalized_term VARCHAR, url VARCHAR, visit_time TIMESTAMP, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "chrome_logins",
        "category": "WEB RELATED",
        "display_name": "Chrome Logins",
        "table_name": "parsed_chrome_logins",
        "source_tool": "ChromiumParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_chrome_logins (
            _row_id BIGINT, browser VARCHAR, profile VARCHAR, origin_url VARCHAR, action_url VARCHAR, username_value VARCHAR, signon_realm VARCHAR, date_created TIMESTAMP, date_last_used TIMESTAMP, times_used INTEGER, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "chrome_top_sites",
        "category": "WEB RELATED",
        "display_name": "Chrome Top Sites",
        "table_name": "parsed_chrome_top_sites",
        "source_tool": "ChromiumParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_chrome_top_sites (
            _row_id BIGINT, url VARCHAR, url_rank INTEGER, title VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "chrome_history",
        "category": "WEB RELATED",
        "display_name": "Chrome History",
        "table_name": "parsed_chrome_history",
        "source_tool": "ChromiumParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_chrome_history (
            _row_id BIGINT, browser VARCHAR, profile VARCHAR, url VARCHAR, title VARCHAR, visit_count INTEGER, typed_count INTEGER, visit_time TIMESTAMP, from_visit BIGINT, transition VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "chrome_visits",
        "category": "WEB RELATED",
        "display_name": "Chrome Web Visits",
        "table_name": "parsed_chrome_visits",
        "source_tool": "ChromiumParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_chrome_visits (
            _row_id BIGINT, url_id BIGINT, visit_time TIMESTAMP, from_visit BIGINT, transition VARCHAR, visit_duration BIGINT, source_file VARCHAR
        );"""
    },

    # Edge
    {
        "artifact_id": "edge_cache",
        "category": "WEB RELATED",
        "display_name": "Edge Cache Data",
        "table_name": "parsed_edge_cache",
        "source_tool": "ChromiumParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_edge_cache (
            _row_id BIGINT, url VARCHAR, key VARCHAR, response_time TIMESTAMP, content_type VARCHAR, size_bytes BIGINT, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "edge_cookies",
        "category": "WEB RELATED",
        "display_name": "Edge Cookies",
        "table_name": "parsed_edge_cookies",
        "source_tool": "ChromiumParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_edge_cookies (
            _row_id BIGINT, host_key VARCHAR, name VARCHAR, value VARCHAR, path VARCHAR, creation_utc TIMESTAMP, expires_utc TIMESTAMP, last_access_utc TIMESTAMP, is_secure BOOLEAN, is_httponly BOOLEAN, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "edge_session",
        "category": "WEB RELATED",
        "display_name": "Edge Current Session & Tabs",
        "table_name": "parsed_edge_session",
        "source_tool": "ChromiumParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_edge_session (
            _row_id BIGINT, browser VARCHAR, profile VARCHAR, window_id BIGINT, tab_id BIGINT, url VARCHAR, title VARCHAR, active BOOLEAN, last_active_time TIMESTAMP, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "edge_downloads",
        "category": "WEB RELATED",
        "display_name": "Edge Downloads",
        "table_name": "parsed_edge_downloads",
        "source_tool": "ChromiumParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_edge_downloads (
            _row_id BIGINT, browser VARCHAR, profile VARCHAR, target_path VARCHAR, tab_url VARCHAR, site_url VARCHAR, total_bytes BIGINT, received_bytes BIGINT, start_time TIMESTAMP, end_time TIMESTAMP, mime_type VARCHAR, danger_type VARCHAR, state VARCHAR, opened INTEGER, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "edge_search_terms",
        "category": "WEB RELATED",
        "display_name": "Edge Keyword Search Terms",
        "table_name": "parsed_edge_search_terms",
        "source_tool": "ChromiumParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_edge_search_terms (
            _row_id BIGINT, term VARCHAR, normalized_term VARCHAR, url VARCHAR, visit_time TIMESTAMP, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "edge_logins",
        "category": "WEB RELATED",
        "display_name": "Edge Logins",
        "table_name": "parsed_edge_logins",
        "source_tool": "ChromiumParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_edge_logins (
            _row_id BIGINT, browser VARCHAR, profile VARCHAR, origin_url VARCHAR, action_url VARCHAR, username_value VARCHAR, signon_realm VARCHAR, date_created TIMESTAMP, date_last_used TIMESTAMP, times_used INTEGER, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "edge_history",
        "category": "WEB RELATED",
        "display_name": "Edge History",
        "table_name": "parsed_edge_history",
        "source_tool": "ChromiumParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_edge_history (
            _row_id BIGINT, browser VARCHAR, profile VARCHAR, url VARCHAR, title VARCHAR, visit_count INTEGER, typed_count INTEGER, visit_time TIMESTAMP, from_visit BIGINT, transition VARCHAR, source_file VARCHAR
        );"""
    },

    # Brave
    {
        "artifact_id": "brave_cookies",
        "category": "WEB RELATED",
        "display_name": "Brave Cookies",
        "table_name": "parsed_brave_cookies",
        "source_tool": "ChromiumParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_brave_cookies (
            _row_id BIGINT, host_key VARCHAR, name VARCHAR, value VARCHAR, path VARCHAR, creation_utc TIMESTAMP, expires_utc TIMESTAMP, last_access_utc TIMESTAMP, is_secure BOOLEAN, is_httponly BOOLEAN, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "brave_downloads",
        "category": "WEB RELATED",
        "display_name": "Brave Downloads",
        "table_name": "parsed_brave_downloads",
        "source_tool": "ChromiumParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_brave_downloads (
            _row_id BIGINT, browser VARCHAR, profile VARCHAR, target_path VARCHAR, tab_url VARCHAR, site_url VARCHAR, total_bytes BIGINT, received_bytes BIGINT, start_time TIMESTAMP, end_time TIMESTAMP, mime_type VARCHAR, danger_type VARCHAR, state VARCHAR, opened INTEGER, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "brave_logins",
        "category": "WEB RELATED",
        "display_name": "Brave Logins",
        "table_name": "parsed_brave_logins",
        "source_tool": "ChromiumParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_brave_logins (
            _row_id BIGINT, browser VARCHAR, profile VARCHAR, origin_url VARCHAR, action_url VARCHAR, username_value VARCHAR, signon_realm VARCHAR, date_created TIMESTAMP, date_last_used TIMESTAMP, times_used INTEGER, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "brave_history",
        "category": "WEB RELATED",
        "display_name": "Brave History",
        "table_name": "parsed_brave_history",
        "source_tool": "ChromiumParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_brave_history (
            _row_id BIGINT, browser VARCHAR, profile VARCHAR, url VARCHAR, title VARCHAR, visit_count INTEGER, typed_count INTEGER, visit_time TIMESTAMP, from_visit BIGINT, transition VARCHAR, source_file VARCHAR
        );"""
    },

    {
        "artifact_id": "brave_session",
        "category": "WEB RELATED",
        "display_name": "Brave Current Session & Tabs",
        "table_name": "parsed_brave_session",
        "source_tool": "ChromiumParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_brave_session (
            _row_id BIGINT, browser VARCHAR, profile VARCHAR, window_id BIGINT, tab_id BIGINT, url VARCHAR, title VARCHAR, active BOOLEAN, last_active_time TIMESTAMP, source_file VARCHAR
        );"""
    },
    # Firefox
    {
        "artifact_id": "firefox_bookmarks",
        "category": "WEB RELATED",
        "display_name": "Firefox Bookmarks",
        "table_name": "parsed_firefox_bookmarks",
        "source_tool": "FirefoxParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_firefox_bookmarks (
            _row_id BIGINT, browser VARCHAR, profile VARCHAR, title VARCHAR, url VARCHAR, date_added TIMESTAMP, date_modified TIMESTAMP, last_modified TIMESTAMP, folder VARCHAR, folder_name VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "firefox_cookies",
        "category": "WEB RELATED",
        "display_name": "Firefox Cookies",
        "table_name": "parsed_firefox_cookies",
        "source_tool": "FirefoxParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_firefox_cookies (
            _row_id BIGINT, browser VARCHAR, profile VARCHAR, host_key VARCHAR, host VARCHAR, name VARCHAR, value VARCHAR, path VARCHAR, creation_utc TIMESTAMP, expires_utc TIMESTAMP, last_access_utc TIMESTAMP, expiry TIMESTAMP, last_accessed TIMESTAMP, creation_time TIMESTAMP, is_secure BOOLEAN, is_httponly BOOLEAN, is_http_only BOOLEAN, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "firefox_downloads",
        "category": "WEB RELATED",
        "display_name": "Firefox Downloads",
        "table_name": "parsed_firefox_downloads",
        "source_tool": "FirefoxParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_firefox_downloads (
            _row_id BIGINT, browser VARCHAR, profile VARCHAR, target_path VARCHAR, url VARCHAR, tab_url VARCHAR, site_url VARCHAR, total_bytes BIGINT, received_bytes BIGINT, start_time TIMESTAMP, end_time TIMESTAMP, mime_type VARCHAR, state VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "firefox_formhistory",
        "category": "WEB RELATED",
        "display_name": "Firefox FormHistory",
        "table_name": "parsed_firefox_formhistory",
        "source_tool": "FirefoxParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_firefox_formhistory (
            _row_id BIGINT, browser VARCHAR, profile VARCHAR, field_name VARCHAR, value VARCHAR, times_used INTEGER, first_used TIMESTAMP, last_used TIMESTAMP, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "firefox_logins",
        "category": "WEB RELATED",
        "display_name": "Firefox Saved Logins",
        "table_name": "parsed_firefox_logins",
        "source_tool": "FirefoxParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_firefox_logins (
            _row_id BIGINT, browser VARCHAR, profile VARCHAR, hostname VARCHAR, origin_url VARCHAR, action_url VARCHAR, http_realm VARCHAR, signon_realm VARCHAR, username_field VARCHAR, username_value VARCHAR, password_field VARCHAR, encrypted_username VARCHAR, encrypted_password VARCHAR, guid VARCHAR, enc_type INTEGER, time_created TIMESTAMP, date_created TIMESTAMP, time_last_used TIMESTAMP, date_last_used TIMESTAMP, time_password_changed TIMESTAMP, times_used INTEGER, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "firefox_history",
        "category": "WEB RELATED",
        "display_name": "Firefox History",
        "table_name": "parsed_firefox_history",
        "source_tool": "FirefoxParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_firefox_history (
            _row_id BIGINT, browser VARCHAR, profile VARCHAR, url VARCHAR, title VARCHAR, visit_count INTEGER, typed_count INTEGER, visit_time TIMESTAMP, from_visit BIGINT, transition VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "web_hindsight",
        "category": "WEB RELATED",
        "display_name": "Hindsight Browser Forensics",
        "table_name": "raw_hindsight",
        "source_tool": "Hindsight",
        "ddl": """CREATE TABLE IF NOT EXISTS raw_hindsight (
            _row_id BIGINT, browser VARCHAR, profile VARCHAR, profile_path VARCHAR, record_type VARCHAR, timestamp_utc TIMESTAMP, visit_time_utc TIMESTAMP, datetime TIMESTAMP, url VARCHAR, title VARCHAR, value VARCHAR, interpretation VARCHAR, source_path VARCHAR, source_file VARCHAR, extra_json VARCHAR
        );"""
    },
    {
        "artifact_id": "ie_history",
        "category": "WEB RELATED",
        "display_name": "Internet Explorer / WebCache History",
        "table_name": "parsed_ie_history",
        "source_tool": "NativeFallbackParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_ie_history (
            _row_id BIGINT, browser VARCHAR, container_name VARCHAR, url VARCHAR, title VARCHAR, accessed_time TIMESTAMP, modified_time TIMESTAMP, visit_count INTEGER, source_file VARCHAR
        );"""
    },


    # -------------------------------------------------------------------------
    # 3. CHAT (Split per chat application, never bundled)
    # -------------------------------------------------------------------------
    {
        "artifact_id": "teams_messages",
        "category": "CHAT",
        "display_name": "Microsoft Teams Messages",
        "table_name": "parsed_teams_messages",
        "source_tool": "ChatParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_teams_messages (
            _row_id BIGINT, app_name VARCHAR, profile VARCHAR, timestamp_utc TIMESTAMP, sender VARCHAR, recipient_channel VARCHAR, message_text VARCHAR, attachment_url VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "teams_calls",
        "category": "CHAT",
        "display_name": "Microsoft Teams Calls & Meetings",
        "table_name": "parsed_teams_calls",
        "source_tool": "ChatParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_teams_calls (
            _row_id BIGINT, app_name VARCHAR, caller VARCHAR, callee VARCHAR, call_type VARCHAR, start_time TIMESTAMP, end_time TIMESTAMP, duration_seconds INTEGER, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "teams_contacts",
        "category": "CHAT",
        "display_name": "Microsoft Teams Contacts",
        "table_name": "parsed_teams_contacts",
        "source_tool": "ChatParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_teams_contacts (
            _row_id BIGINT, app_name VARCHAR, username VARCHAR, display_name VARCHAR, email VARCHAR, phone VARCHAR, status VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "discord_messages",
        "category": "CHAT",
        "display_name": "Discord Messages",
        "table_name": "parsed_discord_messages",
        "source_tool": "ChatParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_discord_messages (
            _row_id BIGINT, app_name VARCHAR, profile VARCHAR, timestamp_utc TIMESTAMP, sender VARCHAR, recipient_channel VARCHAR, message_text VARCHAR, attachment_url VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "discord_cache",
        "category": "CHAT",
        "display_name": "Discord Cache Records",
        "table_name": "parsed_discord_cache",
        "source_tool": "ChatParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_discord_cache (
            _row_id BIGINT, app_name VARCHAR, key VARCHAR, cache_type VARCHAR, file_size BIGINT, timestamp_utc TIMESTAMP, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "slack_messages",
        "category": "CHAT",
        "display_name": "Slack Messages",
        "table_name": "parsed_slack_messages",
        "source_tool": "ChatParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_slack_messages (
            _row_id BIGINT, app_name VARCHAR, profile VARCHAR, timestamp_utc TIMESTAMP, sender VARCHAR, recipient_channel VARCHAR, message_text VARCHAR, attachment_url VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "slack_channels",
        "category": "CHAT",
        "display_name": "Slack Channels & Users",
        "table_name": "parsed_slack_channels",
        "source_tool": "ChatParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_slack_channels (
            _row_id BIGINT, app_name VARCHAR, channel_id VARCHAR, channel_name VARCHAR, topic VARCHAR, member_count INTEGER, created_time TIMESTAMP, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "skype_messages",
        "category": "CHAT",
        "display_name": "Skype Chat Messages",
        "table_name": "parsed_skype_messages",
        "source_tool": "ChatParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_skype_messages (
            _row_id BIGINT, app_name VARCHAR, profile VARCHAR, timestamp_utc TIMESTAMP, sender VARCHAR, recipient_channel VARCHAR, message_text VARCHAR, attachment_url VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "skype_contacts",
        "category": "CHAT",
        "display_name": "Skype Calls & Contacts",
        "table_name": "parsed_skype_contacts",
        "source_tool": "ChatParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_skype_contacts (
            _row_id BIGINT, app_name VARCHAR, username VARCHAR, display_name VARCHAR, email VARCHAR, phone VARCHAR, status VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "whatsapp_messages",
        "category": "CHAT",
        "display_name": "WhatsApp Messages",
        "table_name": "parsed_whatsapp_messages",
        "source_tool": "ChatParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_whatsapp_messages (
            _row_id BIGINT, app_name VARCHAR, profile VARCHAR, timestamp_utc TIMESTAMP, sender VARCHAR, recipient_channel VARCHAR, message_text VARCHAR, attachment_url VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "whatsapp_contacts",
        "category": "CHAT",
        "display_name": "WhatsApp Contacts",
        "table_name": "parsed_whatsapp_contacts",
        "source_tool": "ChatParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_whatsapp_contacts (
            _row_id BIGINT, app_name VARCHAR, username VARCHAR, display_name VARCHAR, phone VARCHAR, status VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "telegram_messages",
        "category": "CHAT",
        "display_name": "Telegram Messages",
        "table_name": "parsed_telegram_messages",
        "source_tool": "ChatParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_telegram_messages (
            _row_id BIGINT, app_name VARCHAR, profile VARCHAR, timestamp_utc TIMESTAMP, sender VARCHAR, recipient_channel VARCHAR, message_text VARCHAR, attachment_url VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "signal_messages",
        "category": "CHAT",
        "display_name": "Signal Messages",
        "table_name": "parsed_signal_messages",
        "source_tool": "ChatParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_signal_messages (
            _row_id BIGINT, app_name VARCHAR, profile VARCHAR, timestamp_utc TIMESTAMP, sender VARCHAR, recipient_channel VARCHAR, message_text VARCHAR, attachment_url VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "chat_messages",
        "category": "CHAT",
        "display_name": "Chat Messages (Combined)",
        "table_name": "parsed_chat_messages",
        "source_tool": "ChatParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_chat_messages (
            _row_id BIGINT, app_name VARCHAR, profile VARCHAR, timestamp_utc TIMESTAMP, sender VARCHAR, recipient_channel VARCHAR, message_text VARCHAR, attachment_url VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "parsed_notifications",
        "category": "OPERATING SYSTEM",
        "display_name": "App Notifications & Toast Alerts",
        "table_name": "parsed_notifications",
        "source_tool": "ChatParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_notifications (
            _row_id BIGINT, notification_id BIGINT, app_id VARCHAR, notification_type VARCHAR, payload VARCHAR, arrival_time TIMESTAMP, expiry_time TIMESTAMP, timestamp_utc TIMESTAMP, title VARCHAR, body VARCHAR, header VARCHAR, action_url VARCHAR, source_path VARCHAR, source_file VARCHAR
        );"""
    },

    # -------------------------------------------------------------------------
    # 4. EMAIL & CALENDAR (Split per client/type)
    # -------------------------------------------------------------------------
    {
        "artifact_id": "outlook_emails",
        "category": "EMAIL & CALENDAR",
        "display_name": "Outlook PST/OST Emails",
        "table_name": "parsed_outlook_emails",
        "source_tool": "EmailParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_outlook_emails (
            _row_id BIGINT, email_format VARCHAR, sender VARCHAR, recipients VARCHAR, cc VARCHAR, bcc VARCHAR, subject VARCHAR, date_utc TIMESTAMP, message_id VARCHAR, body_snippet VARCHAR, attachments_count INTEGER, attachment_names VARCHAR, client_submit_time TIMESTAMP, is_suspicious BOOLEAN, suspicious_indicators VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "outlook_contacts",
        "category": "EMAIL & CALENDAR",
        "display_name": "Outlook Contacts & Calendar",
        "table_name": "parsed_outlook_contacts",
        "source_tool": "EmailParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_outlook_contacts (
            _row_id BIGINT, item_type VARCHAR, display_name VARCHAR, email_address VARCHAR, start_time TIMESTAMP, end_time TIMESTAMP, location VARCHAR, subject VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "email_attachments",
        "category": "EMAIL & CALENDAR",
        "display_name": "Email Attachments",
        "table_name": "parsed_email_attachments",
        "source_tool": "EmailParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_email_attachments (
            _row_id BIGINT, email_id VARCHAR, file_name VARCHAR, file_size BIGINT, mime_type VARCHAR, sha256 VARCHAR, is_malicious BOOLEAN, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "mbox_emails",
        "category": "EMAIL & CALENDAR",
        "display_name": "Thunderbird / MBOX Emails",
        "table_name": "parsed_mbox_emails",
        "source_tool": "EmailParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_mbox_emails (
            _row_id BIGINT, email_format VARCHAR, sender VARCHAR, recipients VARCHAR, cc VARCHAR, bcc VARCHAR, subject VARCHAR, date_utc TIMESTAMP, message_id VARCHAR, body_snippet VARCHAR, attachments_count INTEGER, attachment_names VARCHAR, client_submit_time TIMESTAMP, is_suspicious BOOLEAN, suspicious_indicators VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "winmail_messages",
        "category": "EMAIL & CALENDAR",
        "display_name": "Windows Mail Messages",
        "table_name": "parsed_winmail_messages",
        "source_tool": "EmailParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_winmail_messages (
            _row_id BIGINT, email_format VARCHAR, sender VARCHAR, recipients VARCHAR, cc VARCHAR, bcc VARCHAR, subject VARCHAR, date_utc TIMESTAMP, message_id VARCHAR, body_snippet VARCHAR, attachments_count INTEGER, attachment_names VARCHAR, client_submit_time TIMESTAMP, is_suspicious BOOLEAN, suspicious_indicators VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "emails",
        "category": "EMAIL & CALENDAR",
        "display_name": "Emails (Combined)",
        "table_name": "parsed_emails",
        "source_tool": "EmailParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_emails (
            _row_id BIGINT, email_format VARCHAR, sender VARCHAR, recipients VARCHAR, cc VARCHAR, bcc VARCHAR, subject VARCHAR, date_utc TIMESTAMP, message_id VARCHAR, body_snippet VARCHAR, attachments_count INTEGER, attachment_count INTEGER, attachment_names VARCHAR, client_submit_time TIMESTAMP, is_suspicious BOOLEAN, suspicious_indicators VARCHAR, source_file VARCHAR
        );"""
    },

    # -------------------------------------------------------------------------
    # 5. CLOUD (Split per cloud provider)
    # -------------------------------------------------------------------------
    {
        "artifact_id": "onedrive_files",
        "category": "CLOUD",
        "display_name": "OneDrive Synced Files",
        "table_name": "parsed_onedrive_files",
        "source_tool": "CloudParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_onedrive_files (
            _row_id BIGINT, cloud_provider VARCHAR, account VARCHAR, local_path VARCHAR, cloud_path_or_id VARCHAR, file_size BIGINT, modified_time TIMESTAMP, status VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "onedrive_logs",
        "category": "CLOUD",
        "display_name": "OneDrive Account & Sync Logs",
        "table_name": "parsed_onedrive_logs",
        "source_tool": "CloudParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_onedrive_logs (
            _row_id BIGINT, account_cid VARCHAR, account_tier VARCHAR, user_folder VARCHAR, last_sync_time TIMESTAMP, log_file VARCHAR
        );"""
    },
    {
        "artifact_id": "gdrive_files",
        "category": "CLOUD",
        "display_name": "Google Drive Synced Files",
        "table_name": "parsed_gdrive_files",
        "source_tool": "CloudParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_gdrive_files (
            _row_id BIGINT, cloud_provider VARCHAR, account VARCHAR, local_path VARCHAR, cloud_path_or_id VARCHAR, file_size BIGINT, modified_time TIMESTAMP, status VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "dropbox_files",
        "category": "CLOUD",
        "display_name": "Dropbox Synced Files",
        "table_name": "parsed_dropbox_files",
        "source_tool": "CloudParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_dropbox_files (
            _row_id BIGINT, cloud_provider VARCHAR, account VARCHAR, local_path VARCHAR, cloud_path_or_id VARCHAR, file_size BIGINT, modified_time TIMESTAMP, status VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "cloud_files",
        "category": "CLOUD",
        "display_name": "Cloud Storage Synced Files (Combined)",
        "table_name": "parsed_cloud_files",
        "source_tool": "CloudParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_cloud_files (
            _row_id BIGINT, cloud_provider VARCHAR, account VARCHAR, local_path VARCHAR, cloud_path_or_id VARCHAR, file_size BIGINT, modified_time TIMESTAMP, status VARCHAR, source_file VARCHAR
        );"""
    },

    # -------------------------------------------------------------------------
    # 6. MEDIA
    # -------------------------------------------------------------------------
    {
        "artifact_id": "media_pictures",
        "category": "MEDIA",
        "display_name": "Pictures & EXIF Metadata",
        "table_name": "parsed_media_pictures",
        "source_tool": "MediaParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_media_pictures (
            _row_id BIGINT, file_path VARCHAR, file_name VARCHAR, file_type VARCHAR, file_size_bytes BIGINT, sha256 VARCHAR, camera_make VARCHAR, camera_model VARCHAR, datetime_original TIMESTAMP, software VARCHAR, image_width INTEGER, image_height INTEGER, latitude DOUBLE, longitude DOUBLE, gps_position VARCHAR, gps_coordinates VARCHAR, raw_metadata VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "media_videos",
        "category": "MEDIA",
        "display_name": "Videos & Audio Files",
        "table_name": "parsed_media_videos",
        "source_tool": "MediaParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_media_videos (
            _row_id BIGINT, file_path VARCHAR, file_name VARCHAR, file_type VARCHAR, file_size_bytes BIGINT, sha256 VARCHAR, datetime_original TIMESTAMP, duration_seconds DOUBLE, width INTEGER, height INTEGER, raw_metadata VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "windows_thumbcache",
        "category": "MEDIA",
        "display_name": "Windows Thumbcache",
        "table_name": "parsed_thumbcache",
        "source_tool": "MediaParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_thumbcache (
            _row_id BIGINT, cache_name VARCHAR, cache_file VARCHAR, entry_id BIGINT, entry_hash VARCHAR, cache_type VARCHAR, source_type VARCHAR, file_extension VARCHAR, extension VARCHAR, image_dimensions VARCHAR, image_size_bytes BIGINT, carved_path VARCHAR, carved_file_path VARCHAR, sha256 VARCHAR, carved_at TIMESTAMP, timestamp_utc TIMESTAMP, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "media_ocr_results",
        "category": "MEDIA",
        "display_name": "OCR Extracted Text",
        "table_name": "media_ocr_results",
        "source_tool": "RapidOCR",
        "ddl": """CREATE TABLE IF NOT EXISTS media_ocr_results (
            _row_id BIGINT, file_path VARCHAR, file_name VARCHAR, sha256 VARCHAR, extracted_text VARCHAR, ocr_text VARCHAR, confidence DOUBLE, avg_confidence DOUBLE, engine VARCHAR, line_count INTEGER, char_count INTEGER, scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, source_file VARCHAR
        );"""
    },

    # -------------------------------------------------------------------------
    # 7. DOCUMENTS
    # -------------------------------------------------------------------------
    {
        "artifact_id": "docs_pdf",
        "category": "DOCUMENTS",
        "display_name": "PDF Documents",
        "table_name": "view_docs_pdf",
        "source_tool": "DocumentParser",
        "ddl": """CREATE OR REPLACE VIEW view_docs_pdf AS
            SELECT row_number() OVER () AS _row_id, file_name, file_path, file_size_bytes, created_time, modified_time, author, title, sha256, source_evidence
            FROM (
                SELECT file_name, file_path, file_size_bytes, created_time, modified_time, author, title, sha256, source_evidence,
                       row_number() OVER (PARTITION BY LOWER(file_name), file_size_bytes ORDER BY (CASE WHEN source_evidence = 'parsed_documents_metadata' THEN 1 ELSE 2 END) ASC, modified_time DESC NULLS LAST) AS _final_rn
                FROM (
                    SELECT file_name, file_path, file_size_bytes, created_time, modified_time, author, title, sha256, 'parsed_documents_metadata' AS source_evidence
                    FROM parsed_documents_metadata 
                    WHERE (LOWER(COALESCE(file_type, '')) = 'pdf' OR file_name ILIKE '%.pdf')
                      AND REPLACE(LOWER(COALESCE(file_path, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\winsxs%'
                      AND REPLACE(LOWER(COALESCE(file_path, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\system32%'
                      AND REPLACE(LOWER(COALESCE(file_path, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\syswow64%'
                      AND REPLACE(LOWER(COALESCE(file_path, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\servicing%'
                      AND REPLACE(LOWER(COALESCE(file_path, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\installer%'
                      AND REPLACE(LOWER(COALESCE(file_path, '')), '/', '\\\\') NOT LIKE '%\\\\program files%'
                      AND REPLACE(LOWER(COALESCE(file_path, '')), '/', '\\\\') NOT LIKE '%\\\\programdata\\\\microsoft%'
                      AND LOWER(COALESCE(file_name, '')) NOT IN ('msoirmprotector.doc', 'msoirmprotector.ppt', 'msoirmprotector.xls')
                    UNION ALL
                    SELECT FileName AS file_name, COALESCE(ParentPath, '') || '\\\\' || COALESCE(FileName, '') AS file_path, FileSize AS file_size_bytes, Created0x10 AS created_time, LastModified0x10 AS modified_time, CAST(NULL AS VARCHAR) AS author, CAST(NULL AS VARCHAR) AS title, CAST(NULL AS VARCHAR) AS sha256, 'raw_mft' AS source_evidence
                    FROM (
                        SELECT *, row_number() OVER (PARTITION BY LOWER(COALESCE(ParentPath, '')), LOWER(COALESCE(FileName, '')), FileSize ORDER BY LastModified0x10 DESC NULLS LAST) AS _dup_rn
                        FROM raw_mft 
                        WHERE LOWER(COALESCE(Extension, '')) = '.pdf'
                          AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\winsxs%'
                          AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\system32%'
                          AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\syswow64%'
                          AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\servicing%'
                          AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\installer%'
                          AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\program files%'
                          AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\programdata\\\\microsoft%'
                          AND LOWER(COALESCE(FileName, '')) NOT IN ('msoirmprotector.doc', 'msoirmprotector.ppt', 'msoirmprotector.xls')
                    ) mft_p WHERE _dup_rn = 1
                ) p_sub
            ) ranked_p WHERE _final_rn = 1;"""
    },
    {
        "artifact_id": "docs_word",
        "category": "DOCUMENTS",
        "display_name": "Word Documents (.doc / .docx)",
        "table_name": "view_docs_word",
        "source_tool": "DocumentParser",
        "ddl": """CREATE OR REPLACE VIEW view_docs_word AS
            SELECT row_number() OVER () AS _row_id, file_name, file_path, file_size_bytes, created_time, modified_time, author, title, sha256, source_evidence
            FROM (
                SELECT file_name, file_path, file_size_bytes, created_time, modified_time, author, title, sha256, source_evidence,
                       row_number() OVER (PARTITION BY LOWER(file_name), file_size_bytes ORDER BY (CASE WHEN source_evidence = 'parsed_documents_metadata' THEN 1 ELSE 2 END) ASC, modified_time DESC NULLS LAST) AS _final_rn
                FROM (
                    SELECT file_name, file_path, file_size_bytes, created_time, modified_time, author, title, sha256, 'parsed_documents_metadata' AS source_evidence
                    FROM parsed_documents_metadata 
                    WHERE (LOWER(COALESCE(file_type, '')) IN ('doc', 'docx', 'docm') OR file_name ILIKE '%.docx' OR file_name ILIKE '%.doc')
                      AND REPLACE(LOWER(COALESCE(file_path, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\winsxs%'
                      AND REPLACE(LOWER(COALESCE(file_path, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\system32%'
                      AND REPLACE(LOWER(COALESCE(file_path, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\syswow64%'
                      AND REPLACE(LOWER(COALESCE(file_path, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\servicing%'
                      AND REPLACE(LOWER(COALESCE(file_path, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\installer%'
                      AND REPLACE(LOWER(COALESCE(file_path, '')), '/', '\\\\') NOT LIKE '%\\\\program files%'
                      AND REPLACE(LOWER(COALESCE(file_path, '')), '/', '\\\\') NOT LIKE '%\\\\programdata\\\\microsoft%'
                      AND LOWER(COALESCE(file_name, '')) NOT IN ('msoirmprotector.doc', 'msoirmprotector.ppt', 'msoirmprotector.xls')
                    UNION ALL
                    SELECT FileName AS file_name, COALESCE(ParentPath, '') || '\\\\' || COALESCE(FileName, '') AS file_path, FileSize AS file_size_bytes, Created0x10 AS created_time, LastModified0x10 AS modified_time, CAST(NULL AS VARCHAR) AS author, CAST(NULL AS VARCHAR) AS title, CAST(NULL AS VARCHAR) AS sha256, 'raw_mft' AS source_evidence
                    FROM (
                        SELECT *, row_number() OVER (PARTITION BY LOWER(COALESCE(ParentPath, '')), LOWER(COALESCE(FileName, '')), FileSize ORDER BY LastModified0x10 DESC NULLS LAST) AS _dup_rn
                        FROM raw_mft 
                        WHERE LOWER(COALESCE(Extension, '')) IN ('.doc', '.docx', '.docm')
                          AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\winsxs%'
                          AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\system32%'
                          AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\syswow64%'
                          AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\servicing%'
                          AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\installer%'
                          AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\program files%'
                          AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\programdata\\\\microsoft%'
                          AND LOWER(COALESCE(FileName, '')) NOT IN ('msoirmprotector.doc', 'msoirmprotector.ppt', 'msoirmprotector.xls')
                    ) mft_w WHERE _dup_rn = 1
                ) w_sub
            ) ranked_w WHERE _final_rn = 1;"""
    },
    {
        "artifact_id": "docs_excel",
        "category": "DOCUMENTS",
        "display_name": "Excel Spreadsheets (.xls / .xlsx / .csv)",
        "table_name": "view_docs_excel",
        "source_tool": "DocumentParser",
        "ddl": """CREATE OR REPLACE VIEW view_docs_excel AS
            SELECT row_number() OVER () AS _row_id, file_name, file_path, file_size_bytes, created_time, modified_time, author, title, sha256, source_evidence
            FROM (
                SELECT file_name, file_path, file_size_bytes, created_time, modified_time, author, title, sha256, source_evidence,
                       row_number() OVER (PARTITION BY LOWER(file_name), file_size_bytes ORDER BY (CASE WHEN source_evidence = 'parsed_documents_metadata' THEN 1 ELSE 2 END) ASC, modified_time DESC NULLS LAST) AS _final_rn
                FROM (
                    SELECT file_name, file_path, file_size_bytes, created_time, modified_time, author, title, sha256, 'parsed_documents_metadata' AS source_evidence
                    FROM parsed_documents_metadata 
                    WHERE (LOWER(COALESCE(file_type, '')) IN ('xls', 'xlsx', 'xlsm', 'csv') OR file_name ILIKE '%.xlsx' OR file_name ILIKE '%.xls' OR file_name ILIKE '%.csv')
                      AND REPLACE(LOWER(COALESCE(file_path, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\winsxs%'
                      AND REPLACE(LOWER(COALESCE(file_path, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\system32%'
                      AND REPLACE(LOWER(COALESCE(file_path, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\syswow64%'
                      AND REPLACE(LOWER(COALESCE(file_path, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\servicing%'
                      AND REPLACE(LOWER(COALESCE(file_path, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\installer%'
                      AND REPLACE(LOWER(COALESCE(file_path, '')), '/', '\\\\') NOT LIKE '%\\\\program files%'
                      AND REPLACE(LOWER(COALESCE(file_path, '')), '/', '\\\\') NOT LIKE '%\\\\programdata\\\\microsoft%'
                      AND LOWER(COALESCE(file_name, '')) NOT IN ('msoirmprotector.doc', 'msoirmprotector.ppt', 'msoirmprotector.xls')
                    UNION ALL
                    SELECT FileName AS file_name, COALESCE(ParentPath, '') || '\\\\' || COALESCE(FileName, '') AS file_path, FileSize AS file_size_bytes, Created0x10 AS created_time, LastModified0x10 AS modified_time, CAST(NULL AS VARCHAR) AS author, CAST(NULL AS VARCHAR) AS title, CAST(NULL AS VARCHAR) AS sha256, 'raw_mft' AS source_evidence
                    FROM (
                        SELECT *, row_number() OVER (PARTITION BY LOWER(COALESCE(ParentPath, '')), LOWER(COALESCE(FileName, '')), FileSize ORDER BY LastModified0x10 DESC NULLS LAST) AS _dup_rn
                        FROM raw_mft 
                        WHERE LOWER(COALESCE(Extension, '')) IN ('.xls', '.xlsx', '.xlsm', '.csv')
                          AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\winsxs%'
                          AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\system32%'
                          AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\syswow64%'
                          AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\servicing%'
                          AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\installer%'
                          AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\program files%'
                          AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\programdata\\\\microsoft%'
                          AND LOWER(COALESCE(FileName, '')) NOT IN ('msoirmprotector.doc', 'msoirmprotector.ppt', 'msoirmprotector.xls')
                    ) mft_e WHERE _dup_rn = 1
                ) e_sub
            ) ranked_e WHERE _final_rn = 1;"""
    },
    {
        "artifact_id": "docs_ppt",
        "category": "DOCUMENTS",
        "display_name": "PowerPoint Presentations (.ppt / .pptx)",
        "table_name": "view_docs_ppt",
        "source_tool": "DocumentParser",
        "ddl": """CREATE OR REPLACE VIEW view_docs_ppt AS
            SELECT row_number() OVER () AS _row_id, file_name, file_path, file_size_bytes, created_time, modified_time, author, title, sha256, source_evidence
            FROM (
                SELECT file_name, file_path, file_size_bytes, created_time, modified_time, author, title, sha256, source_evidence,
                       row_number() OVER (PARTITION BY LOWER(file_name), file_size_bytes ORDER BY (CASE WHEN source_evidence = 'parsed_documents_metadata' THEN 1 ELSE 2 END) ASC, modified_time DESC NULLS LAST) AS _final_rn
                FROM (
                    SELECT file_name, file_path, file_size_bytes, created_time, modified_time, author, title, sha256, 'parsed_documents_metadata' AS source_evidence
                    FROM parsed_documents_metadata 
                    WHERE (LOWER(COALESCE(file_type, '')) IN ('ppt', 'pptx', 'pptm') OR file_name ILIKE '%.pptx' OR file_name ILIKE '%.ppt')
                      AND REPLACE(LOWER(COALESCE(file_path, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\winsxs%'
                      AND REPLACE(LOWER(COALESCE(file_path, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\system32%'
                      AND REPLACE(LOWER(COALESCE(file_path, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\syswow64%'
                      AND REPLACE(LOWER(COALESCE(file_path, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\servicing%'
                      AND REPLACE(LOWER(COALESCE(file_path, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\installer%'
                      AND REPLACE(LOWER(COALESCE(file_path, '')), '/', '\\\\') NOT LIKE '%\\\\program files%'
                      AND REPLACE(LOWER(COALESCE(file_path, '')), '/', '\\\\') NOT LIKE '%\\\\programdata\\\\microsoft%'
                      AND LOWER(COALESCE(file_name, '')) NOT IN ('msoirmprotector.doc', 'msoirmprotector.ppt', 'msoirmprotector.xls')
                    UNION ALL
                    SELECT FileName AS file_name, COALESCE(ParentPath, '') || '\\\\' || COALESCE(FileName, '') AS file_path, FileSize AS file_size_bytes, Created0x10 AS created_time, LastModified0x10 AS modified_time, CAST(NULL AS VARCHAR) AS author, CAST(NULL AS VARCHAR) AS title, CAST(NULL AS VARCHAR) AS sha256, 'raw_mft' AS source_evidence
                    FROM (
                        SELECT *, row_number() OVER (PARTITION BY LOWER(COALESCE(ParentPath, '')), LOWER(COALESCE(FileName, '')), FileSize ORDER BY LastModified0x10 DESC NULLS LAST) AS _dup_rn
                        FROM raw_mft 
                        WHERE LOWER(COALESCE(Extension, '')) IN ('.ppt', '.pptx', '.pptm')
                          AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\winsxs%'
                          AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\system32%'
                          AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\syswow64%'
                          AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\servicing%'
                          AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\installer%'
                          AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\program files%'
                          AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\programdata\\\\microsoft%'
                          AND LOWER(COALESCE(FileName, '')) NOT IN ('msoirmprotector.doc', 'msoirmprotector.ppt', 'msoirmprotector.xls')
                    ) mft_ppt WHERE _dup_rn = 1
                ) p_sub
            ) ranked_ppt WHERE _final_rn = 1;"""
    },
    {
        "artifact_id": "docs_txt",
        "category": "DOCUMENTS",
        "display_name": "Plain Text & Configuration Files",
        "table_name": "view_docs_txt",
        "source_tool": "DocumentParser",
        "ddl": """CREATE OR REPLACE VIEW view_docs_txt AS
            SELECT row_number() OVER () AS _row_id, file_name, file_path, file_size_bytes, created_time, modified_time, author, title, sha256, encoding, line_count, text_preview, source_evidence
            FROM (
                SELECT file_name, file_path, file_size_bytes, created_time, modified_time, author, title, sha256, encoding, line_count, text_preview, source_evidence,
                       row_number() OVER (
                           PARTITION BY LOWER(COALESCE(file_name, '')), COALESCE(file_size_bytes, -1)
                           ORDER BY (CASE source_evidence WHEN 'parsed_text_documents' THEN 0 WHEN 'parsed_documents_metadata' THEN 1 WHEN 'raw_mft' THEN 2 ELSE 3 END) ASC,
                                    modified_time DESC NULLS LAST
                       ) AS _final_rn
                FROM (
                    SELECT file_name, file_path, file_size_bytes, created_time, modified_time,
                           CAST(NULL AS VARCHAR) AS author, CAST(NULL AS VARCHAR) AS title, sha256,
                           encoding, line_count, text_preview, 'parsed_text_documents' AS source_evidence
                    FROM parsed_text_documents
                    UNION ALL
                    SELECT file_name, file_path, file_size_bytes, created_time, modified_time, author, title, sha256,
                           CAST(NULL AS VARCHAR) AS encoding, CAST(NULL AS INTEGER) AS line_count, CAST(NULL AS VARCHAR) AS text_preview,
                           'parsed_documents_metadata' AS source_evidence
                    FROM parsed_documents_metadata
                    WHERE (LOWER(COALESCE(file_type, '')) IN ('txt', 'log', 'ini', 'cfg', 'conf', 'json', 'xml', 'yaml', 'yml', 'md', 'ps1', 'bat', 'vbs')
                           OR file_name ILIKE '%.txt' OR file_name ILIKE '%.log' OR file_name ILIKE '%.ini' OR file_name ILIKE '%.cfg' OR file_name ILIKE '%.conf' OR file_name ILIKE '%.json' OR file_name ILIKE '%.xml')
                      AND REPLACE(LOWER(COALESCE(file_path, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\winsxs%'
                      AND REPLACE(LOWER(COALESCE(file_path, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\system32%'
                      AND REPLACE(LOWER(COALESCE(file_path, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\syswow64%'
                      AND REPLACE(LOWER(COALESCE(file_path, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\servicing%'
                      AND REPLACE(LOWER(COALESCE(file_path, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\installer%'
                      AND REPLACE(LOWER(COALESCE(file_path, '')), '/', '\\\\') NOT LIKE '%\\\\program files%'
                      AND REPLACE(LOWER(COALESCE(file_path, '')), '/', '\\\\') NOT LIKE '%\\\\programdata\\\\microsoft%'
                      AND LOWER(COALESCE(file_name, '')) NOT IN ('msoirmprotector.doc', 'msoirmprotector.ppt', 'msoirmprotector.xls')
                    UNION ALL
                    SELECT FileName AS file_name, COALESCE(ParentPath, '') || '\\\\' || COALESCE(FileName, '') AS file_path, FileSize AS file_size_bytes, Created0x10 AS created_time, LastModified0x10 AS modified_time,
                           CAST(NULL AS VARCHAR) AS author, CAST(NULL AS VARCHAR) AS title, CAST(NULL AS VARCHAR) AS sha256,
                           CAST(NULL AS VARCHAR) AS encoding, CAST(NULL AS INTEGER) AS line_count, CAST(NULL AS VARCHAR) AS text_preview,
                           'raw_mft' AS source_evidence
                    FROM (
                        SELECT *, row_number() OVER (PARTITION BY LOWER(COALESCE(ParentPath, '')), LOWER(COALESCE(FileName, '')), FileSize ORDER BY LastModified0x10 DESC NULLS LAST) AS _dup_rn
                        FROM raw_mft
                        WHERE LOWER(COALESCE(Extension, '')) IN ('.txt', '.log', '.ini', '.cfg', '.conf', '.json', '.xml', '.yaml', '.yml')
                          AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\winsxs%'
                          AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\system32%'
                          AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\syswow64%'
                          AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\servicing%'
                          AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\installer%'
                          AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\program files%'
                          AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\programdata\\\\microsoft%'
                          AND LOWER(COALESCE(FileName, '')) NOT IN ('msoirmprotector.doc', 'msoirmprotector.ppt', 'msoirmprotector.xls')
                    ) mft_t WHERE _dup_rn = 1
                    UNION ALL
                    SELECT file_name, COALESCE(vfs_path, parent_path || '/' || file_name) AS file_path, size_bytes AS file_size_bytes, si_created AS created_time, si_modified AS modified_time,
                           CAST(NULL AS VARCHAR) AS author, CAST(NULL AS VARCHAR) AS title, CAST(NULL AS VARCHAR) AS sha256,
                           CAST(NULL AS VARCHAR) AS encoding, CAST(NULL AS INTEGER) AS line_count, CAST(NULL AS VARCHAR) AS text_preview,
                           'vfs_files' AS source_evidence
                    FROM vfs_files
                    WHERE COALESCE(is_dir, FALSE) = FALSE
                      AND LOWER(regexp_extract(COALESCE(file_name, ''), '(\\.[^.\\\\/]+)$', 1)) IN ('.txt', '.log', '.ini', '.cfg', '.conf', '.json', '.xml', '.yaml', '.yml', '.md', '.csv', '.rtf', '.ps1', '.bat', '.vbs', '.cmd')
                      AND REPLACE(LOWER(COALESCE(vfs_path, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\winsxs%'
                      AND REPLACE(LOWER(COALESCE(vfs_path, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\system32%'
                ) t_sub
            ) ranked_t WHERE _final_rn = 1;"""
    },
    {
        "artifact_id": "view_documents",
        "category": "DOCUMENTS",
        "display_name": "Discovered Documents",
        "table_name": "view_documents",
        "source_tool": "FileSystemNormalizer",
        "ddl": """CREATE OR REPLACE VIEW view_documents AS
            SELECT row_number() OVER () AS _row_id, file_name, file_path, extension, file_size_bytes, created_time, modified_time, source_evidence
            FROM (
                SELECT file_name, file_path,
                       LOWER(CASE WHEN file_name LIKE '%.%' THEN '.' || regexp_extract(file_name, '\\.([^.]+)$', 1) ELSE '.' || COALESCE(extension, '') END) AS extension,
                       file_size_bytes, created_time, modified_time, 'parsed_text_documents' AS source_evidence
                FROM parsed_text_documents
                UNION ALL
                SELECT file_name, file_path,
                       LOWER(CASE WHEN file_name LIKE '%.%' THEN '.' || regexp_extract(file_name, '\\.([^.]+)$', 1) ELSE '.' || COALESCE(file_type, '') END) AS extension,
                       file_size_bytes, created_time, modified_time, 'parsed_documents_metadata' AS source_evidence
                FROM parsed_documents_metadata
                UNION ALL
                SELECT file_name, file_path, extension, file_size_bytes, created_time, modified_time, source_evidence
                FROM (
                    SELECT FileName AS file_name, COALESCE(ParentPath, '') || '\\' || COALESCE(FileName, '') AS file_path, LOWER(Extension) AS extension, FileSize AS file_size_bytes, Created0x10 AS created_time, LastModified0x10 AS modified_time, 'raw_mft' AS source_evidence,
                           row_number() OVER (PARTITION BY LOWER(COALESCE(ParentPath, '')), LOWER(COALESCE(FileName, '')), FileSize ORDER BY LastModified0x10 DESC NULLS LAST) AS _dup_rn
                    FROM raw_mft
                    WHERE LOWER(COALESCE(Extension, '')) IN ('.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.csv')
                      AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\') NOT LIKE '%\\windows\\winsxs%'
                      AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\') NOT LIKE '%\\windows\\system32%'
                      AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\') NOT LIKE '%\\windows\\syswow64%'
                      AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\') NOT LIKE '%\\windows\\servicing%'
                      AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\') NOT LIKE '%\\windows\\installer%'
                      AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\') NOT LIKE '%\\program files%'
                      AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\') NOT LIKE '%\\programdata\\microsoft%'
                      AND LOWER(COALESCE(FileName, '')) NOT IN ('msoirmprotector.doc', 'msoirmprotector.ppt', 'msoirmprotector.xls')
                ) doc_sub WHERE _dup_rn = 1
            ) all_docs;"""
    },

    # -------------------------------------------------------------------------
    # 8. EVENT LOGS (Dedicated Category)
    # -------------------------------------------------------------------------
    {
        "artifact_id": "os_evtx",
        "category": "EVENT LOGS",
        "display_name": "All Event Logs (Combined)",
        "table_name": "raw_evtx",
        "source_tool": "EvtxECmd.exe",
        "ddl": """CREATE TABLE IF NOT EXISTS raw_evtx (
            _row_id BIGINT,
            RecordNumber BIGINT,
            EventRecordId BIGINT,
            TimeCreated TIMESTAMP,
            EventId INTEGER,
            Level VARCHAR,
            Provider VARCHAR,
            Channel VARCHAR,
            ProcessId INTEGER,
            ThreadId INTEGER,
            Computer VARCHAR,
            UserId VARCHAR,
            MapDescription VARCHAR,
            UserName VARCHAR,
            RemoteHost VARCHAR,
            PayloadData1 VARCHAR,
            PayloadData2 VARCHAR,
            PayloadData3 VARCHAR,
            PayloadData4 VARCHAR,
            PayloadData5 VARCHAR,
            PayloadData6 VARCHAR,
            Payload VARCHAR,
            ExecutableInfo VARCHAR,
            SourceFile VARCHAR
        );"""
    },

    # -------------------------------------------------------------------------
    # 9. OPERATING SYSTEM (Granular Windows OS Artifacts)
    # -------------------------------------------------------------------------
    {
        "artifact_id": "os_amcache_files",
        "category": "OPERATING SYSTEM",
        "display_name": "Amcache Application Files",
        "table_name": "raw_amcache_files",
        "source_tool": "AmcacheParser.exe",
        "ddl": """CREATE TABLE IF NOT EXISTS raw_amcache_files (
            _row_id BIGINT, FileKeyLastWriteTimestamp TIMESTAMP, Name VARCHAR, FullPath VARCHAR, SHA1 VARCHAR, Size BIGINT, FileExtension VARCHAR, LinkDate TIMESTAMP, ProductName VARCHAR, Company VARCHAR
        );"""
    },
    {
        "artifact_id": "os_amcache_programs",
        "category": "OPERATING SYSTEM",
        "display_name": "Amcache Installed Programs",
        "table_name": "raw_amcache_programs",
        "source_tool": "AmcacheParser.exe",
        "ddl": """CREATE TABLE IF NOT EXISTS raw_amcache_programs (
            _row_id BIGINT, Name VARCHAR, InstallDate TIMESTAMP, UninstallString VARCHAR, Publisher VARCHAR, Version VARCHAR, InstalledCheck VARCHAR
        );"""
    },
    {
        "artifact_id": "os_amcache_shortcuts",
        "category": "OPERATING SYSTEM",
        "display_name": "Amcache LNK Shortcuts",
        "table_name": "raw_amcache_shortcuts",
        "source_tool": "AmcacheParser.exe",
        "ddl": """CREATE TABLE IF NOT EXISTS raw_amcache_shortcuts (
            _row_id BIGINT, LnkName VARCHAR, TargetPath VARCHAR, FileSize BIGINT, LastWriteTime TIMESTAMP
        );"""
    },
    {
        "artifact_id": "os_amcache_devices",
        "category": "OPERATING SYSTEM",
        "display_name": "Amcache Device Containers",
        "table_name": "raw_amcache_devices",
        "source_tool": "AmcacheParser.exe",
        "ddl": """CREATE TABLE IF NOT EXISTS raw_amcache_devices (
            _row_id BIGINT, KeyLastWriteTimestamp TIMESTAMP, Id VARCHAR, FriendlyName VARCHAR, ModelName VARCHAR, Manufacturer VARCHAR
        );"""
    },
    {
        "artifact_id": "os_shimcache",
        "category": "OPERATING SYSTEM",
        "display_name": "AppCompatCache (ShimCache)",
        "table_name": "raw_shimcache",
        "source_tool": "AppCompatCacheParser.exe",
        "ddl": """CREATE TABLE IF NOT EXISTS raw_shimcache (
            _row_id BIGINT, Path VARCHAR, LastModifiedTimeUTC TIMESTAMP, Size BIGINT, Executed VARCHAR
        );"""
    },
    {
        "artifact_id": "os_autoruns",
        "category": "OPERATING SYSTEM",
        "display_name": "Parsed Autoruns (Registry & Startup)",
        "table_name": "parsed_autoruns",
        "source_tool": "RegistryParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_autoruns (
            _row_id BIGINT, entry_name VARCHAR, autorun_type VARCHAR, category VARCHAR, location VARCHAR, key_path VARCHAR, value_name VARCHAR, command VARCHAR, image_path VARCHAR, launch_string VARCHAR, enabled BOOLEAN, publisher VARCHAR, username VARCHAR, last_modified_utc TIMESTAMP, last_write_utc TIMESTAMP, hive_path VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "os_bam_dam",
        "category": "OPERATING SYSTEM",
        "display_name": "Parsed BAM/DAM Execution",
        "table_name": "parsed_bam_dam",
        "source_tool": "RegistryParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_bam_dam (
            _row_id BIGINT, service_type VARCHAR, user_sid VARCHAR, username VARCHAR, executable_path VARCHAR, app_name VARCHAR, sequence_number INTEGER, last_execution_utc TIMESTAMP, execution_time_utc TIMESTAMP, key_path VARCHAR, hive_path VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "os_userassist",
        "category": "OPERATING SYSTEM",
        "display_name": "Parsed UserAssist Execution",
        "table_name": "parsed_userassist",
        "source_tool": "RegistryParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_userassist (
            _row_id BIGINT, username VARCHAR, user_sid VARCHAR, guid VARCHAR, rot13_name VARCHAR, program_path VARCHAR, run_count INTEGER, focus_count INTEGER, focus_time_ms BIGINT, last_executed_utc TIMESTAMP, last_run_utc TIMESTAMP, key_path VARCHAR, hive_path VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "os_user_accounts",
        "category": "OPERATING SYSTEM",
        "display_name": "Windows User Accounts (SAM / Registry)",
        "table_name": "parsed_user_accounts",
        "source_tool": "RegistryParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_user_accounts (
            _row_id BIGINT, rid INTEGER, user_sid VARCHAR, sid VARCHAR, username VARCHAR, full_name VARCHAR, comment VARCHAR, account_type VARCHAR, is_disabled BOOLEAN, is_locked BOOLEAN, password_not_required BOOLEAN, login_count INTEGER, logon_count INTEGER, invalid_login_count INTEGER, last_login_utc TIMESTAMP, last_logon_utc TIMESTAMP, last_password_change_utc TIMESTAMP, password_reset_utc TIMESTAMP, last_failed_login_utc TIMESTAMP, account_created_utc TIMESTAMP, created_utc TIMESTAMP, profile_path VARCHAR, hive_path VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "os_windows_services",
        "category": "OPERATING SYSTEM",
        "display_name": "Windows Services Configuration",
        "table_name": "parsed_windows_services",
        "source_tool": "RegistryParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_windows_services (
            _row_id BIGINT, service_name VARCHAR, display_name VARCHAR, description VARCHAR, image_path VARCHAR, service_dll VARCHAR, start_type VARCHAR, service_type VARCHAR, object_name VARCHAR, account_name VARCHAR, error_control VARCHAR, failure_command VARCHAR, last_modified_utc TIMESTAMP, last_write_utc TIMESTAMP, key_path VARCHAR, hive_path VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "os_registry_mru",
        "category": "OPERATING SYSTEM",
        "display_name": "Registry MRU (RecentDocs / OpenSavePidl / RunMRU)",
        "table_name": "parsed_registry_mru",
        "source_tool": "RegistryParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_registry_mru (
            _row_id BIGINT, mru_type VARCHAR, category VARCHAR, username VARCHAR, key_path VARCHAR, value_name VARCHAR, mru_position INTEGER, target_path VARCHAR, target_name VARCHAR, entry_value VARCHAR, extension VARCHAR, last_modified_utc TIMESTAMP, last_write_utc TIMESTAMP, hive_path VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "os_network_profiles",
        "category": "OPERATING SYSTEM",
        "display_name": "Windows Network Profiles & Interfaces",
        "table_name": "parsed_network_profiles",
        "source_tool": "RegistryParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_network_profiles (
            _row_id BIGINT, profile_guid VARCHAR, profile_name VARCHAR, description VARCHAR, network_type VARCHAR, category VARCHAR, managed BOOLEAN, dns_suffix VARCHAR, default_gateway_mac VARCHAR, ssid VARCHAR, ip_address VARCHAR, dhcp_server VARCHAR, date_created_utc TIMESTAMP, first_connected_utc TIMESTAMP, date_last_connected_utc TIMESTAMP, last_connected_utc TIMESTAMP, key_path VARCHAR, hive_path VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "os_wer_reports",
        "category": "OPERATING SYSTEM",
        "display_name": "Windows Error Reporting (WER)",
        "table_name": "parsed_wer_reports",
        "source_tool": "CorporateIRParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_wer_reports (
            _row_id BIGINT, report_id VARCHAR, report_type VARCHAR, event_type VARCHAR, app_name VARCHAR, app_path VARCHAR, app_version VARCHAR, fault_module_name VARCHAR, fault_module_version VARCHAR, exception_code VARCHAR, fault_offset VARCHAR, bucket_id VARCHAR, username VARCHAR, report_timestamp_utc TIMESTAMP, report_time_utc TIMESTAMP, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "vfs_partitions",
        "category": "OPERATING SYSTEM",
        "display_name": "Disk Partitions & Volumes",
        "table_name": "vfs_partitions",
        "source_tool": "DiskImageVFS",
        "ddl": """CREATE TABLE IF NOT EXISTS vfs_partitions (
            _row_id BIGINT, part_index INTEGER, partition_index INTEGER, addr BIGINT, label VARCHAR, volume_label VARCHAR, description VARCHAR, fs_type VARCHAR, start_sector BIGINT, offset_bytes BIGINT, start_offset_bytes BIGINT, length_sectors BIGINT, size_bytes BIGINT, volume_serial VARCHAR, serial_number VARCHAR, is_boot BOOLEAN, is_bootable BOOLEAN, flags VARCHAR
        );"""
    },
    {
        "artifact_id": "vfs_files",
        "category": "OPERATING SYSTEM",
        "display_name": "File System Metadata (VFS)",
        "table_name": "vfs_files",
        "source_tool": "DiskImageVFS",
        "ddl": """CREATE TABLE IF NOT EXISTS vfs_files (
            _row_id BIGINT, part_index INTEGER, partition_index INTEGER, fs_type VARCHAR, inode BIGINT, parent_inode BIGINT, vfs_path VARCHAR, staged_rel_path VARCHAR, file_name VARCHAR, extension VARCHAR, parent_path VARCHAR, size_bytes BIGINT, is_dir BOOLEAN, is_directory BOOLEAN, is_allocated BOOLEAN, is_deleted BOOLEAN, si_created TIMESTAMP, si_modified TIMESTAMP, si_accessed TIMESTAMP, si_changed TIMESTAMP, fn_created TIMESTAMP, fn_modified TIMESTAMP, fn_accessed TIMESTAMP, fn_changed TIMESTAMP, si_created_utc TIMESTAMP, si_modified_utc TIMESTAMP, si_accessed_utc TIMESTAMP, si_changed_utc TIMESTAMP, fn_created_utc TIMESTAMP, fn_modified_utc TIMESTAMP, fn_accessed_utc TIMESTAMP, fn_changed_utc TIMESTAMP, mft_entry BIGINT, vss_store_index INTEGER
        );"""
    },
    {
        "artifact_id": "fs_vss",
        "category": "OPERATING SYSTEM",
        "display_name": "Volume Shadow Copies (VSS)",
        "table_name": "vfs_shadow_copies",
        "source_tool": "VSSShadowMount",
        "ddl": """CREATE TABLE IF NOT EXISTS vfs_shadow_copies (
            _row_id BIGINT, vss_index INTEGER, store_index INTEGER, part_index INTEGER, partition_index INTEGER, store_id VARCHAR, vss_id VARCHAR, volume_label VARCHAR, shadow_copy_guid VARCHAR, volume_guid VARCHAR, creation_time TIMESTAMP, creation_time_utc TIMESTAMP, size_bytes BIGINT, shadow_copy_size BIGINT, store_size_bytes BIGINT, attribute_flags BIGINT, machine_name VARCHAR, originating_machine VARCHAR, servicing_machine VARCHAR, staged_prefix VARCHAR, files_staged INTEGER, status VARCHAR
        );"""
    },
    {
        "artifact_id": "carve_files",
        "category": "OPERATING SYSTEM",
        "display_name": "Carved Unallocated Files",
        "table_name": "parsed_carved_files",
        "source_tool": "DataCarver",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_carved_files (
            _row_id BIGINT, carve_id VARCHAR, file_name VARCHAR, file_type VARCHAR, extension VARCHAR, mime_type VARCHAR, offset_bytes BIGINT, byte_offset BIGINT, sector_offset BIGINT, partition_index INTEGER, size_bytes BIGINT, sha256 VARCHAR, md5 VARCHAR, carved_rel_path VARCHAR, carved_path VARCHAR, source_region VARCHAR, header_sig VARCHAR, validated BOOLEAN, is_unallocated BOOLEAN, source_evidence VARCHAR, timestamp_utc TIMESTAMP, carved_at TIMESTAMP
        );"""
    },
    {
        "artifact_id": "view_autoruns",
        "category": "OPERATING SYSTEM",
        "display_name": "Autorun & Startup Items",
        "table_name": "view_autoruns",
        "source_tool": "RECmd.exe / RegistryParser",
        "ddl": """CREATE OR REPLACE VIEW view_autoruns AS
            SELECT
                row_number() OVER () AS _row_id,
                COALESCE(entry_name, value_name) AS entry_name,
                COALESCE(autorun_type, category, 'Autorun') AS Category,
                COALESCE(key_path, location) AS KeyPath,
                COALESCE(value_name, entry_name) AS ValueName,
                COALESCE(command, launch_string, image_path) AS ValueData,
                image_path,
                username,
                COALESCE(last_modified_utc, last_write_utc) AS LastWriteTimestamp,
                COALESCE(hive_path, source_file) AS HivePath,
                'parsed_autoruns' AS source_table
            FROM parsed_autoruns
            UNION ALL
            SELECT
                row_number() OVER () AS _row_id,
                ValueName AS entry_name,
                Category,
                KeyPath,
                ValueName,
                ValueData,
                ValueData2 AS image_path,
                CAST(NULL AS VARCHAR) AS username,
                LastWriteTimestamp,
                HivePath,
                'raw_recmd' AS source_table
            FROM raw_recmd
            WHERE (Category ILIKE '%Run%' OR KeyPath ILIKE '%CurrentVersion\\Run%' OR KeyPath ILIKE '%Services%');"""
    },
    {
        "artifact_id": "view_bam_dam",
        "category": "OPERATING SYSTEM",
        "display_name": "Background Activity Moderator (BAM/DAM)",
        "table_name": "view_bam_dam",
        "source_tool": "RECmd.exe / RegistryParser",
        "ddl": """CREATE OR REPLACE VIEW view_bam_dam AS
            SELECT
                row_number() OVER () AS _row_id,
                COALESCE(service_type, 'BAM') AS Category,
                COALESCE(executable_path, app_name) AS executable_path,
                user_sid,
                username,
                COALESCE(key_path, 'SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\' || COALESCE(user_sid, '')) AS KeyPath,
                COALESCE(executable_path, app_name) AS ValueName,
                COALESCE(CAST(COALESCE(last_execution_utc, execution_time_utc) AS VARCHAR), '') AS ValueData,
                COALESCE(last_execution_utc, execution_time_utc) AS LastWriteTimestamp,
                COALESCE(hive_path, source_file) AS HivePath,
                'parsed_bam_dam' AS source_table
            FROM parsed_bam_dam
            UNION ALL
            SELECT
                row_number() OVER () AS _row_id,
                Category,
                ValueName AS executable_path,
                CAST(NULL AS VARCHAR) AS user_sid,
                CAST(NULL AS VARCHAR) AS username,
                KeyPath,
                ValueName,
                ValueData,
                LastWriteTimestamp,
                HivePath,
                'raw_recmd' AS source_table
            FROM raw_recmd
            WHERE (KeyPath ILIKE '%bam%' OR KeyPath ILIKE '%dam%' OR Description ILIKE '%bam%' OR Description ILIKE '%dam%');"""
    },
    {
        "artifact_id": "fs_jumplist_auto",
        "category": "OPERATING SYSTEM",
        "display_name": "Jump Lists - Automatic Destinations",
        "table_name": "raw_jlecmd_auto",
        "source_tool": "JLECmd.exe",
        "ddl": """CREATE TABLE IF NOT EXISTS raw_jlecmd_auto (
            _row_id BIGINT, SourceFile VARCHAR, SourceCreated TIMESTAMP, SourceModified TIMESTAMP, SourceAccessed TIMESTAMP, AppId VARCHAR, AppIdDescription VARCHAR, EntryNumber INTEGER, TargetCreated TIMESTAMP, TargetModified TIMESTAMP, TargetAccessed TIMESTAMP, Path VARCHAR, DriveSerialNumber VARCHAR
        );"""
    },
    {
        "artifact_id": "fs_jumplist_custom",
        "category": "OPERATING SYSTEM",
        "display_name": "Jump Lists - Custom Destinations",
        "table_name": "raw_jlecmd_custom",
        "source_tool": "JLECmd.exe",
        "ddl": """CREATE TABLE IF NOT EXISTS raw_jlecmd_custom (
            _row_id BIGINT, SourceFile VARCHAR, SourceCreated TIMESTAMP, SourceModified TIMESTAMP, SourceAccessed TIMESTAMP, AppId VARCHAR, AppIdDescription VARCHAR, EntryNumber INTEGER, TargetCreated TIMESTAMP, TargetModified TIMESTAMP, TargetAccessed TIMESTAMP, Path VARCHAR
        );"""
    },
    {
        "artifact_id": "fs_lnk",
        "category": "OPERATING SYSTEM",
        "display_name": "LNK Files & Recent Shortcuts",
        "table_name": "raw_lecmd",
        "source_tool": "LECmd.exe",
        "ddl": """CREATE TABLE IF NOT EXISTS raw_lecmd (
            _row_id BIGINT, SourceFilename VARCHAR, SourceCreated TIMESTAMP, SourceModified TIMESTAMP, SourceAccessed TIMESTAMP, TargetCreated TIMESTAMP, TargetModified TIMESTAMP, TargetAccessed TIMESTAMP, LocalPath VARCHAR, RelativePath VARCHAR, DriveSerialNumber VARCHAR, VolumeLabel VARCHAR
        );"""
    },
    {
        "artifact_id": "fs_mft",
        "category": "OPERATING SYSTEM",
        "display_name": "NTFS Master File Table ($MFT)",
        "table_name": "raw_mft",
        "source_tool": "MFTECmd.exe",
        "ddl": """CREATE TABLE IF NOT EXISTS raw_mft (
            _row_id BIGINT, EntryNumber BIGINT, SequenceNumber INTEGER, InUse BOOLEAN, IsDirectory BOOLEAN, ParentEntryNumber BIGINT, ParentSequenceNumber INTEGER, ParentPath VARCHAR, FileName VARCHAR, Extension VARCHAR, FileSize BIGINT, Created0x10 TIMESTAMP, Created0x30 TIMESTAMP, LastModified0x10 TIMESTAMP, LastModified0x30 TIMESTAMP, LastAccess0x10 TIMESTAMP, LastAccess0x30 TIMESTAMP, LastRecordChange0x10 TIMESTAMP, LastRecordChange0x30 TIMESTAMP, TimestampsLogicalInconsistency BOOLEAN
        );"""
    },
    {
        "artifact_id": "fs_usnjrnl",
        "category": "OPERATING SYSTEM",
        "display_name": "NTFS USN Change Journal ($J)",
        "table_name": "raw_usnjrnl",
        "source_tool": "MFTECmd.exe",
        "ddl": """CREATE TABLE IF NOT EXISTS raw_usnjrnl (
            _row_id BIGINT, EntryNumber BIGINT, SequenceNumber INTEGER, ParentEntryNumber BIGINT, ParentSequenceNumber INTEGER, FileName VARCHAR, FileAttributes VARCHAR, UpdateReasons VARCHAR, UpdateTimestamp TIMESTAMP
        );"""
    },
    {
        "artifact_id": "powershell_console_history",
        "category": "OPERATING SYSTEM",
        "display_name": "PowerShell Console Host History",
        "table_name": "parsed_powershell_history",
        "source_tool": "CorporateIRParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_powershell_history (
            _row_id BIGINT, username VARCHAR, user_name VARCHAR, command VARCHAR, command_length INTEGER, is_suspicious BOOLEAN, contains_suspicious BOOLEAN, matched_pattern VARCHAR, line_number INTEGER, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "os_prefetch",
        "category": "OPERATING SYSTEM",
        "display_name": "Prefetch Files - Execution",
        "table_name": "raw_pecmd",
        "source_tool": "PECmd.exe",
        "ddl": """CREATE TABLE IF NOT EXISTS raw_pecmd (
            _row_id BIGINT, SourceCreated TIMESTAMP, SourceModified TIMESTAMP, SourceAccessed TIMESTAMP, SourceFilename VARCHAR, ExecutableName VARCHAR, Hash VARCHAR, Size BIGINT, Version VARCHAR, RunCount INTEGER, LastRun TIMESTAMP, PreviousRun0 TIMESTAMP, PreviousRun1 TIMESTAMP, PreviousRun2 TIMESTAMP, PreviousRun3 TIMESTAMP, PreviousRun4 TIMESTAMP, PreviousRun5 TIMESTAMP, PreviousRun6 TIMESTAMP, PreviousRun7 TIMESTAMP, Volume0Name VARCHAR, Volume0Serial VARCHAR, Volume0Created TIMESTAMP, Directories VARCHAR, FilesLoaded VARCHAR
        );"""
    },
    {
        "artifact_id": "raw_pecmd_timeline",
        "category": "OPERATING SYSTEM",
        "display_name": "Prefetch Timeline",
        "table_name": "raw_pecmd_timeline",
        "source_tool": "PECmd.exe",
        "ddl": """CREATE TABLE IF NOT EXISTS raw_pecmd_timeline (
            _row_id BIGINT, RunTime TIMESTAMP, ExecutableName VARCHAR, Hash VARCHAR, SourceCreated TIMESTAMP, SourceFilename VARCHAR
        );"""
    },
    {
        "artifact_id": "fs_recyclebin",
        "category": "OPERATING SYSTEM",
        "display_name": "Recycle Bin ($I / $R)",
        "table_name": "raw_rbcmd",
        "source_tool": "RBCmd.exe",
        "ddl": """CREATE TABLE IF NOT EXISTS raw_rbcmd (
            _row_id BIGINT, SourceName VARCHAR, FileName VARCHAR, FileSize BIGINT, DeletedOn TIMESTAMP, OriginalPath VARCHAR
        );"""
    },
    {
        "artifact_id": "registry_recmd",
        "category": "OPERATING SYSTEM",
        "display_name": "Registry Hive Batch Analysis (RECmd)",
        "table_name": "raw_recmd",
        "source_tool": "RECmd.exe",
        "ddl": """CREATE TABLE IF NOT EXISTS raw_recmd (
            _row_id BIGINT, HivePath VARCHAR, HiveType VARCHAR, Category VARCHAR, Description VARCHAR, KeyPath VARCHAR, ValueName VARCHAR, ValueType VARCHAR, ValueData VARCHAR, ValueData2 VARCHAR, ValueData3 VARCHAR, Comment VARCHAR, LastWriteTimestamp TIMESTAMP
        );"""
    },
    {
        "artifact_id": "parsed_rmm_sessions",
        "category": "OPERATING SYSTEM",
        "display_name": "Remote Desktop & RMM Logs (AnyDesk / TeamViewer)",
        "table_name": "parsed_rmm_sessions",
        "source_tool": "CorporateIRParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_rmm_sessions (
            _row_id BIGINT, app_name VARCHAR, rmm_product VARCHAR, session_id VARCHAR, remote_identifier VARCHAR, connection_type VARCHAR, start_time_utc TIMESTAMP, end_time_utc TIMESTAMP, remote_ip VARCHAR, remote_id VARCHAR, alias VARCHAR, local_user VARCHAR, auth_type VARCHAR, connection_result VARCHAR, details VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "tasks_scheduled",
        "category": "OPERATING SYSTEM",
        "display_name": "Scheduled Tasks",
        "table_name": "parsed_scheduled_tasks",
        "source_tool": "CorporateIRParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_scheduled_tasks (
            _row_id BIGINT, task_name VARCHAR, task_path VARCHAR, enabled BOOLEAN, execute_command VARCHAR, command VARCHAR, arguments VARCHAR, working_dir VARCHAR, author VARCHAR, date_created TIMESTAMP, triggers_summary VARCHAR, triggers VARCHAR, is_suspicious BOOLEAN, suspicious_indicators VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "fs_shellbags",
        "category": "OPERATING SYSTEM",
        "display_name": "Shellbags Folder Access",
        "table_name": "raw_shellbags",
        "source_tool": "SBECmd.exe",
        "ddl": """CREATE TABLE IF NOT EXISTS raw_shellbags (
            _row_id BIGINT, BagPath VARCHAR, ValueName VARCHAR, FolderType VARCHAR, Created TIMESTAMP, Modified TIMESTAMP, Accessed TIMESTAMP, NodeSlot VARCHAR, MRU VARCHAR
        );"""
    },
    {
        "artifact_id": "network_srum_app",
        "category": "OPERATING SYSTEM",
        "display_name": "SRUM Application Resource Usage",
        "table_name": "raw_srum_app",
        "source_tool": "SrumECmd.exe",
        "ddl": """CREATE TABLE IF NOT EXISTS raw_srum_app (
            _row_id BIGINT, Timestamp TIMESTAMP, AppId VARCHAR, ExeInfo VARCHAR, UserId VARCHAR, ForegroundCycleTime BIGINT, BackgroundCycleTime BIGINT, FaceTime BIGINT
        );"""
    },
    {
        "artifact_id": "network_srum_net",
        "category": "OPERATING SYSTEM",
        "display_name": "SRUM Network Data Usage",
        "table_name": "raw_srum_net",
        "source_tool": "SrumECmd.exe",
        "ddl": """CREATE TABLE IF NOT EXISTS raw_srum_net (
            _row_id BIGINT, Timestamp TIMESTAMP, AppId VARCHAR, ExeInfo VARCHAR, UserId VARCHAR, BytesSent BIGINT, BytesReceived BIGINT, InterfaceLuid BIGINT
        );"""
    },
    {
        "artifact_id": "network_srum_conn",
        "category": "OPERATING SYSTEM",
        "display_name": "SRUM Network Connections",
        "table_name": "raw_srum_conn",
        "source_tool": "SrumECmd.exe",
        "ddl": """CREATE TABLE IF NOT EXISTS raw_srum_conn (
            _row_id BIGINT, Timestamp TIMESTAMP, AppId VARCHAR, ExeInfo VARCHAR, UserId VARCHAR, ConnectedTime TIMESTAMP, ConnectDurationSeconds BIGINT, InterfaceLuid BIGINT
        );"""
    },
    {
        "artifact_id": "usb_devices",
        "category": "OPERATING SYSTEM",
        "display_name": "USB & External Storage Devices",
        "table_name": "parsed_usb_devices",
        "source_tool": "USBDeviceCorrelator",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_usb_devices (
            _row_id BIGINT, vendor_id VARCHAR, product_id VARCHAR, revision VARCHAR, serial_number VARCHAR, friendly_name VARCHAR, drive_letter VARCHAR, volume_guid VARCHAR, first_connected_utc TIMESTAMP, last_connected_utc TIMESTAMP, source_evidence VARCHAR
        );"""
    },
    {
        "artifact_id": "view_usb_devices",
        "category": "OPERATING SYSTEM",
        "display_name": "USB Registry Activity",
        "table_name": "view_usb_devices",
        "source_tool": "RECmd.exe",
        "ddl": """CREATE OR REPLACE VIEW view_usb_devices AS
            SELECT * FROM raw_recmd WHERE (KeyPath LIKE '%USBSTOR%' OR KeyPath LIKE '%MountedDevices%' OR KeyPath LIKE '%EMDMgmt%' OR Description LIKE '%USB%');"""
    },
    {
        "artifact_id": "view_userassist",
        "category": "OPERATING SYSTEM",
        "display_name": "UserAssist GUI Execution",
        "table_name": "view_userassist",
        "source_tool": "RECmd.exe / RegistryParser",
        "ddl": """CREATE OR REPLACE VIEW view_userassist AS
            SELECT
                row_number() OVER () AS _row_id,
                'UserAssist' AS Category,
                program_path,
                rot13_name,
                guid,
                run_count,
                focus_count,
                focus_time_ms,
                username,
                COALESCE(key_path, 'NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\' || COALESCE(guid, '')) AS KeyPath,
                COALESCE(program_path, rot13_name) AS ValueName,
                'RunCount=' || COALESCE(CAST(run_count AS VARCHAR), '0') AS ValueData,
                COALESCE(last_executed_utc, last_run_utc) AS LastWriteTimestamp,
                COALESCE(hive_path, source_file) AS HivePath,
                'parsed_userassist' AS source_table
            FROM parsed_userassist
            UNION ALL
            SELECT
                row_number() OVER () AS _row_id,
                Category,
                ValueName AS program_path,
                CAST(NULL AS VARCHAR) AS rot13_name,
                CAST(NULL AS VARCHAR) AS guid,
                TRY_CAST(ValueData2 AS INTEGER) AS run_count,
                CAST(NULL AS INTEGER) AS focus_count,
                CAST(NULL AS BIGINT) AS focus_time_ms,
                CAST(NULL AS VARCHAR) AS username,
                KeyPath,
                ValueName,
                ValueData,
                LastWriteTimestamp,
                HivePath,
                'raw_recmd' AS source_table
            FROM raw_recmd
            WHERE (Category ILIKE '%UserAssist%' OR Description ILIKE '%UserAssist%' OR KeyPath ILIKE '%UserAssist%');"""
    },
    {
        "artifact_id": "os_wpn_notifications",
        "category": "OPERATING SYSTEM",
        "display_name": "Windows Push Notifications (WPN)",
        "table_name": "parsed_wpn_notifications",
        "source_tool": "CorporateIRParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_wpn_notifications (
            _row_id BIGINT, notification_id VARCHAR, app_id VARCHAR, notification_type VARCHAR, arrival_time_utc TIMESTAMP, expiry_time_utc TIMESTAMP, payload VARCHAR, payload_text VARCHAR, timestamp_utc TIMESTAMP, title VARCHAR, body VARCHAR, header VARCHAR, action_url VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "os_wxt_activity",
        "category": "OPERATING SYSTEM",
        "display_name": "Windows Timeline (ActivitiesCache.db)",
        "table_name": "raw_wxt_activity",
        "source_tool": "WxTCmd.exe",
        "ddl": """CREATE TABLE IF NOT EXISTS raw_wxt_activity (
            _row_id BIGINT, Id VARCHAR, AppId VARCHAR, StartTime TIMESTAMP, EndTime TIMESTAMP, LastModifiedTime TIMESTAMP, ActivityType VARCHAR, DisplayText VARCHAR, Description VARCHAR, ContentUrl VARCHAR
        );"""
    },
    {
        "artifact_id": "os_recentfilecache",
        "category": "OPERATING SYSTEM",
        "display_name": "RecentFileCache",
        "table_name": "raw_recentfilecache",
        "source_tool": "RecentFileCacheParser.exe",
        "ddl": """CREATE TABLE IF NOT EXISTS raw_recentfilecache (
            _row_id BIGINT, Filename VARCHAR
        );"""
    },
    {
        "artifact_id": "network_sum",
        "category": "OPERATING SYSTEM",
        "display_name": "User Access Logging (SUM)",
        "table_name": "raw_sum",
        "source_tool": "SumECmd.exe",
        "ddl": """CREATE TABLE IF NOT EXISTS raw_sum (
            _row_id BIGINT, DateVal TIMESTAMP, RoleGuid VARCHAR, RoleName VARCHAR, ServerName VARCHAR, TotalAccesses BIGINT
        );"""
    },

    # -------------------------------------------------------------------------
    # 10. MALWARE & YARA
    # -------------------------------------------------------------------------
    {
        "artifact_id": "malware_yara_hits",
        "category": "MALWARE & YARA",
        "display_name": "YARA Rule Hits",
        "table_name": "artifact_yara_hits",
        "source_tool": "FileEnrichmentEngine",
        "ddl": """CREATE TABLE IF NOT EXISTS artifact_yara_hits (
            _row_id BIGINT, file_path VARCHAR NOT NULL, file_name VARCHAR NOT NULL, extension VARCHAR, size_bytes BIGINT, sha256 VARCHAR, rule_name VARCHAR NOT NULL, rule_namespace VARCHAR, pattern_identifier VARCHAR, match_offset BIGINT, match_length BIGINT, match_data_hex VARCHAR, severity VARCHAR, category VARCHAR, description VARCHAR, mitre_attack VARCHAR, scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );"""
    },
    {
        "artifact_id": "file_enrichment",
        "category": "MALWARE & YARA",
        "display_name": "File Entropy, Hashes & IOC Enrichment",
        "table_name": "file_enrichment",
        "source_tool": "FileEnrichmentEngine",
        "ddl": """CREATE TABLE IF NOT EXISTS file_enrichment (
            _row_id BIGINT, enrichment_id BIGINT, file_path VARCHAR NOT NULL, file_name VARCHAR NOT NULL, extension VARCHAR, size_bytes BIGINT, md5 VARCHAR, sha256 VARCHAR, shannon_entropy DOUBLE, is_pe BOOLEAN DEFAULT FALSE, pe_imphash VARCHAR, pe_compile_time TIMESTAMP, pe_sections_info VARCHAR, is_high_entropy BOOLEAN DEFAULT FALSE, yara_hit_count INTEGER DEFAULT 0, ioc_hit_count INTEGER DEFAULT 0, yara_rules_matched VARCHAR, yara_match_offsets VARCHAR, ocr_extracted_text VARCHAR, archive_parent VARCHAR, scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );"""
    },
    {
        "artifact_id": "malware_stinger_hits",
        "category": "MALWARE & YARA",
        "display_name": "Trellix Stinger & PE Threat Hits",
        "table_name": "artifact_stinger_hits",
        "source_tool": "TrellixStingerEngine",
        "ddl": """CREATE TABLE IF NOT EXISTS artifact_stinger_hits (
            _row_id BIGINT, file_path VARCHAR NOT NULL, file_name VARCHAR NOT NULL, sha256 VARCHAR, malware_name VARCHAR, detection_type VARCHAR, action_taken VARCHAR, engine VARCHAR DEFAULT 'Trellix Stinger', engine_version VARCHAR, details VARCHAR, scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );"""
    },
    {
        "artifact_id": "malware_all_detections",
        "category": "MALWARE & YARA",
        "display_name": "All Malware & Threat Detections",
        "table_name": "view_all_malware_detections",
        "source_tool": "MalwareScanner",
        "ddl": """CREATE OR REPLACE VIEW view_all_malware_detections AS
            SELECT row_number() OVER () AS _row_id, sub.*
            FROM (
                SELECT
                    file_name,
                    file_path,
                    sha256,
                    malware_name AS threat_name,
                    malware_name AS detection_name,
                    detection_type,
                    CASE WHEN detection_type ILIKE '%Heuristic%' THEN 'High' ELSE 'Critical' END AS severity,
                    COALESCE(action_taken, 'Reported') AS action_taken,
                    COALESCE(engine, 'Trellix Stinger') AS engine,
                    details,
                    scanned_at,
                    'artifact_stinger_hits' AS table_name,
                    _row_id AS source_row_id
                FROM artifact_stinger_hits
                UNION ALL
                SELECT
                    file_name,
                    file_path,
                    sha256,
                    rule_name AS threat_name,
                    rule_name AS detection_name,
                    'YARA-X Rule Match' AS detection_type,
                    COALESCE(severity, 'High') AS severity,
                    'Flagged' AS action_taken,
                    'YARA-X' AS engine,
                    'Namespace: ' || COALESCE(rule_namespace, 'default') || ' | Pattern: ' || COALESCE(pattern_identifier, 'string') || ' @ ' || COALESCE(CAST(match_offset AS VARCHAR), '0') AS details,
                    scanned_at,
                    'artifact_yara_hits' AS table_name,
                    _row_id AS source_row_id
                FROM artifact_yara_hits
            ) sub;"""
    },
]


def _batch_count_tables(
    cursor: duckdb.DuckDBPyConnection,
    table_names: List[str],
    chunk_size: int = 25,
) -> Dict[str, int]:
    """Count rows across multiple tables/views in batched UNION ALL queries to minimize DuckDB round-trips."""
    counts: Dict[str, int] = {}
    unique_names = list(dict.fromkeys(table_names))
    for idx in range(0, len(unique_names), chunk_size):
        chunk = unique_names[idx : idx + chunk_size]
        if not chunk:
            continue
        union_sql = " UNION ALL ".join(
            [
                f"SELECT '{t.replace(chr(39), chr(39) * 2)}' AS t, COUNT(*) AS c FROM \"{t.replace(chr(34), chr(34) * 2)}\""
                for t in chunk
            ]
        )
        try:
            for t_name, cnt_val in cursor.execute(union_sql).fetchall():
                counts[str(t_name)] = int(cnt_val or 0)
        except Exception:
            for t in chunk:
                try:
                    c_val = cursor.execute(
                        f'SELECT COUNT(*) FROM "{t.replace(chr(34), chr(34) * 2)}";'
                    ).fetchone()[0]
                    counts[t] = int(c_val or 0)
                except Exception:
                    pass
    return counts


_ALTER_ADD_COL_RE = re.compile(
    r"^\s*ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?\"?([A-Za-z0-9_]+)\"?\s+ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?\"?([A-Za-z0-9_]+)\"?",
    re.IGNORECASE,
)


def _parse_alter_add_col(stmt: str) -> Optional[Tuple[str, str]]:
    m = _ALTER_ADD_COL_RE.match(stmt or "")
    if not m:
        return None
    return (m.group(1).lower(), m.group(2).lower())


def register_evtx_granular_views(
    conn: duckdb.DuckDBPyConnection,
    case_id: Optional[str] = None,
    _in_tx: bool = False,
) -> List[Dict[str, Any]]:
    """
    Dynamically creates dedicated DuckDB views for EVERY individual .evtx file present in raw_evtx
    and registers each view in artifact_registry under category = 'EVENT LOGS'.
    Also ensures 'All Event Logs (Combined)' (raw_evtx) is registered under 'EVENT LOGS'.
    """
    created_views: List[Dict[str, Any]] = []
    started_tx = False
    try:
        cursor = conn.cursor()
        # Check if raw_evtx table exists and has rows
        tables = [
            r[0]
            for r in cursor.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main' AND table_name = 'raw_evtx';"
            ).fetchall()
        ]
        if not tables:
            return created_views

        count_res = cursor.execute("SELECT COUNT(*) FROM raw_evtx;").fetchone()
        if not count_res or count_res[0] is None:
            return created_views
        total_evtx = count_res[0]

        if not _in_tx:
            try:
                cursor.execute("BEGIN TRANSACTION;")
                started_tx = True
            except Exception:
                started_tx = False

        # 1. Register All Event Logs (Combined) under EVENT LOGS
        cursor.execute(
            """
            INSERT INTO artifact_registry (
                artifact_id, category, display_name, table_name, source_tool, row_count, last_updated
            ) VALUES ('os_evtx', 'EVENT LOGS', 'All Event Logs (Combined)', 'raw_evtx', 'EvtxECmd.exe', ?, CURRENT_TIMESTAMP)
            ON CONFLICT (artifact_id) DO UPDATE SET
                category = 'EVENT LOGS',
                display_name = 'All Event Logs (Combined)',
                table_name = 'raw_evtx',
                row_count = EXCLUDED.row_count,
                last_updated = now();
            """,
            [total_evtx],
        )

        if total_evtx == 0:
            if started_tx:
                cursor.execute("COMMIT;")
                started_tx = False
            return created_views

        # Introspect available columns in raw_evtx
        cols = [r[1] for r in cursor.execute("PRAGMA table_info(raw_evtx);").fetchall()]
        has_source_file = "SourceFile" in cols
        has_channel = "Channel" in cols

        # Query distinct .evtx files and their exact counts
        if has_source_file and has_channel:
            evtx_query = """
                SELECT
                    COALESCE(
                        NULLIF(regexp_extract(COALESCE(SourceFile, ''), '([^\\\\/]+\\.evtx)$', 1), ''),
                        NULLIF(regexp_extract(COALESCE(Channel, ''), '([^\\\\/]+\\.evtx)$', 1), ''),
                        Channel || '.evtx'
                    ) AS evtx_file,
                    COUNT(*) AS cnt
                FROM raw_evtx
                WHERE COALESCE(SourceFile, Channel) IS NOT NULL
                GROUP BY evtx_file
                HAVING cnt > 0
                ORDER BY cnt DESC;
            """
        elif has_source_file:
            evtx_query = """
                SELECT
                    regexp_extract(COALESCE(SourceFile, ''), '([^\\\\/]+\\.evtx)$', 1) AS evtx_file,
                    COUNT(*) AS cnt
                FROM raw_evtx
                WHERE SourceFile IS NOT NULL AND length(trim(SourceFile)) > 0
                GROUP BY evtx_file
                HAVING cnt > 0
                ORDER BY cnt DESC;
            """
        elif has_channel:
            evtx_query = """
                SELECT Channel || '.evtx' AS evtx_file, COUNT(*) AS cnt
                FROM raw_evtx
                WHERE Channel IS NOT NULL
                GROUP BY Channel
                HAVING cnt > 0
                ORDER BY cnt DESC;
            """
        else:
            if started_tx:
                cursor.execute("COMMIT;")
                started_tx = False
            return created_views

        file_counts = cursor.execute(evtx_query).fetchall()
        if not file_counts:
            if started_tx:
                cursor.execute("COMMIT;")
                started_tx = False
            return created_views

        for row in file_counts:
            if row is None or len(row) < 2:
                continue
            evtx_file, cnt = row[0], row[1]
            if not evtx_file or not str(evtx_file).strip() or cnt is None:
                continue
            evtx_file_str = str(evtx_file).strip()
            # Clean display name: %4 -> /
            display_name = evtx_file_str.replace("%4", "/")
            raw_base = evtx_file_str[:-5] if evtx_file_str.lower().endswith(".evtx") else evtx_file_str
            clean_base = display_name[:-5] if display_name.lower().endswith(".evtx") else display_name

            # Sanitize view name: view_evtx_<sanitized>
            sanitized_stem = re.sub(r"[^a-zA-Z0-9_]", "_", raw_base.lower()).strip("_")
            if not sanitized_stem:
                sanitized_stem = "log"
            view_name = f"view_evtx_{sanitized_stem}"
            art_id = f"evtx_{sanitized_stem}"

            # Escape single quotes and ILIKE wildcards (\\, %, _) in filenames for SQL safety
            escaped_file = evtx_file_str.replace("'", "''")
            escaped_like_file = (
                evtx_file_str.replace("\\", "\\\\")
                .replace("%", "\\%")
                .replace("_", "\\_")
                .replace("'", "''")
            )
            escaped_raw_base = raw_base.replace("'", "''")
            escaped_clean_base = clean_base.replace("'", "''")

            # Create filtered view in DuckDB
            if has_source_file and has_channel:
                view_sql = f"""
                CREATE OR REPLACE VIEW "{view_name}" AS
                SELECT * FROM raw_evtx
                WHERE regexp_extract(COALESCE(SourceFile, ''), '([^\\\\/]+\\.evtx)$', 1) = '{escaped_file}'
                   OR SourceFile ILIKE '%{escaped_like_file}' ESCAPE '\\'
                   OR Channel = '{escaped_raw_base}'
                   OR Channel = '{escaped_clean_base}';
                """
            elif has_source_file:
                view_sql = f"""
                CREATE OR REPLACE VIEW "{view_name}" AS
                SELECT * FROM raw_evtx
                WHERE regexp_extract(COALESCE(SourceFile, ''), '([^\\\\/]+\\.evtx)$', 1) = '{escaped_file}'
                   OR SourceFile ILIKE '%{escaped_like_file}' ESCAPE '\\';
                """
            else:
                view_sql = f"""
                CREATE OR REPLACE VIEW "{view_name}" AS
                SELECT * FROM raw_evtx
                WHERE Channel = '{escaped_raw_base}';
                """

            cursor.execute(view_sql)

            # Register in artifact_registry under EVENT LOGS
            cursor.execute(
                """
                INSERT INTO artifact_registry (
                    artifact_id, category, display_name, table_name, source_tool, row_count, last_updated
                ) VALUES (?, 'EVENT LOGS', ?, ?, 'EvtxECmd.exe', ?, CURRENT_TIMESTAMP)
                ON CONFLICT (artifact_id) DO UPDATE SET
                    category = 'EVENT LOGS',
                    display_name = EXCLUDED.display_name,
                    table_name = EXCLUDED.table_name,
                    row_count = EXCLUDED.row_count,
                    last_updated = now();
                """,
                [art_id, display_name, view_name, cnt],
            )

            created_views.append({
                "artifact_id": art_id,
                "category": "EVENT LOGS",
                "display_name": display_name,
                "table_name": view_name,
                "row_count": cnt,
            })

        if started_tx:
            cursor.execute("COMMIT;")
            started_tx = False

    except Exception as ex:
        if started_tx:
            try:
                conn.cursor().execute("ROLLBACK;")
            except Exception:
                pass
        print(f"[Schema] Error registering dynamic evtx views: {ex}")

    return created_views


register_dynamic_evtx_views = register_evtx_granular_views


def _acquire_case_lock(case_id: Optional[str]):
    if not case_id:
        from contextlib import nullcontext
        return nullcontext()
    try:
        from backend.db.engine import DuckDBManager
        return DuckDBManager.get_lock(case_id)
    except Exception:
        from contextlib import nullcontext
        return nullcontext()


def sync_granular_artifacts(
    conn: duckdb.DuckDBPyConnection,
    case_id: Optional[str] = None,
    _in_tx: bool = False,
) -> None:
    """
    Synchronizes granular browser, chat, email, cloud, media, document, OCR, and event log tables
    from any populated combined or raw tables, ensuring zero row duplication and zero data loss.
    """
    with _acquire_case_lock(case_id):
        started_tx = False
        try:
            cursor = conn.cursor()
            tables_in_db = set(
                r[0]
                for r in cursor.execute(
                    "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
                ).fetchall()
            )

            candidate_sources = [
                t
                for t in (
                    "parsed_browser_history",
                    "parsed_browser_downloads",
                    "parsed_browser_logins",
                    "parsed_chat_messages",
                    "parsed_cloud_files",
                    "parsed_emails",
                    "artifact_ocr_results",
                    "media_ocr_results",
                    "parsed_media_exif",
                )
                if t in tables_in_db
            ]
            source_totals = _batch_count_tables(cursor, candidate_sources, chunk_size=25)

            if not _in_tx:
                try:
                    cursor.execute("BEGIN TRANSACTION;")
                    started_tx = True
                except Exception:
                    started_tx = False

            def safe_sync_table(
                src: str,
                dst: str,
                filter_sql: str,
                exclude_cols: tuple = ("_row_id",),
                dedup_keys: Optional[tuple] = None,
                coalesce_map: Optional[Dict[str, Tuple[str, ...]]] = None,
            ) -> None:
                if src not in tables_in_db or dst not in tables_in_db:
                    return
                if source_totals.get(src, 0) <= 0:
                    return
                try:
                    src_cnt = cursor.execute(f'SELECT COUNT(*) FROM "{src}" WHERE {filter_sql};').fetchone()[0]
                    if not src_cnt:
                        return
                except Exception:
                    return
                src_cols = [r[1] for r in cursor.execute(f'PRAGMA table_info("{src}");').fetchall()]
                dst_cols = [r[1] for r in cursor.execute(f'PRAGMA table_info("{dst}");').fetchall()]
                common = [c for c in dst_cols if c not in exclude_cols and (
                    c in src_cols or (coalesce_map and c in coalesce_map and any(alt in src_cols for alt in coalesce_map[c]))
                )]
                if not common:
                    return
                cols_str = ", ".join([f'"{c}"' for c in common])
                s_exprs: List[str] = []
                src_expr_by_col: Dict[str, str] = {}
                for c in common:
                    if coalesce_map and c in coalesce_map:
                        present_alts = [alt for alt in coalesce_map[c] if alt in src_cols]
                        if len(present_alts) > 1:
                            inner = ", ".join([f'_s."{alt}"' for alt in present_alts])
                            expr = f'COALESCE({inner})'
                        elif len(present_alts) == 1:
                            expr = f'_s."{present_alts[0]}"'
                        else:
                            expr = f'_s."{c}"'
                    else:
                        expr = f'_s."{c}"'
                    src_expr_by_col[c] = expr
                    s_exprs.append(f'{expr} AS "{c}"')
                s_cols_str = ", ".join(s_exprs)
                not_exists_sql = ""
                if dedup_keys:
                    valid_keys = [k for k in dedup_keys if k in dst_cols and (k in src_cols or k in src_expr_by_col)]
                    if valid_keys:
                        key_preds = " AND ".join([
                            f'_d."{k}" IS NOT DISTINCT FROM {src_expr_by_col.get(k, "_s." + chr(34) + k + chr(34))}'
                            for k in valid_keys
                        ])
                        not_exists_sql = f' AND NOT EXISTS (SELECT 1 FROM "{dst}" _d WHERE {key_preds})'
                if "_row_id" in dst_cols:
                    max_id = cursor.execute(f'SELECT COALESCE(MAX(_row_id), 0) FROM "{dst}";').fetchone()[0] or 0
                    cursor.execute(f"""
                        INSERT INTO "{dst}" (_row_id, {cols_str})
                        SELECT {int(max_id)} + row_number() OVER (), {cols_str}
                        FROM (
                            SELECT {s_cols_str} FROM "{src}" _s WHERE ({filter_sql}){not_exists_sql}
                            EXCEPT
                            SELECT {cols_str} FROM "{dst}"
                        ) _diff;
                    """)
                else:
                    cursor.execute(f"""
                        INSERT INTO "{dst}" ({cols_str})
                        SELECT {s_cols_str} FROM "{src}" _s WHERE ({filter_sql}){not_exists_sql}
                        EXCEPT
                        SELECT {cols_str} FROM "{dst}";
                    """)

            # 1. Web Browsers History Sync
            _bh_coal = {"visit_time": ("visit_time", "visit_time_utc")}
            safe_sync_table("parsed_browser_history", "parsed_chrome_history", "LOWER(COALESCE(browser, '')) IN ('chrome', 'chromium')", dedup_keys=("url", "visit_time"), coalesce_map=_bh_coal)
            safe_sync_table("parsed_browser_history", "parsed_edge_history", "LOWER(COALESCE(browser, '')) LIKE '%edge%'", dedup_keys=("url", "visit_time"), coalesce_map=_bh_coal)
            safe_sync_table("parsed_browser_history", "parsed_brave_history", "LOWER(COALESCE(browser, '')) LIKE '%brave%'", dedup_keys=("url", "visit_time"), coalesce_map=_bh_coal)
            safe_sync_table("parsed_browser_history", "parsed_firefox_history", "LOWER(COALESCE(browser, '')) LIKE '%firefox%'", dedup_keys=("url", "visit_time"), coalesce_map=_bh_coal)

            # 2. Web Browsers Downloads Sync
            _bd_coal = {"start_time": ("start_time", "start_time_utc"), "end_time": ("end_time", "end_time_utc")}
            safe_sync_table("parsed_browser_downloads", "parsed_chrome_downloads", "LOWER(COALESCE(browser, '')) IN ('chrome', 'chromium')", dedup_keys=("target_path",), coalesce_map=_bd_coal)
            safe_sync_table("parsed_browser_downloads", "parsed_edge_downloads", "LOWER(COALESCE(browser, '')) LIKE '%edge%'", dedup_keys=("target_path",), coalesce_map=_bd_coal)
            safe_sync_table("parsed_browser_downloads", "parsed_brave_downloads", "LOWER(COALESCE(browser, '')) LIKE '%brave%'", dedup_keys=("target_path",), coalesce_map=_bd_coal)
            safe_sync_table("parsed_browser_downloads", "parsed_firefox_downloads", "LOWER(COALESCE(browser, '')) LIKE '%firefox%'", dedup_keys=("target_path",), coalesce_map=_bd_coal)

            # 3. Web Browsers Logins Sync
            _bl_coal = {"date_created": ("date_created", "date_created_utc"), "date_last_used": ("date_last_used", "date_last_used_utc")}
            safe_sync_table("parsed_browser_logins", "parsed_chrome_logins", "LOWER(COALESCE(browser, '')) IN ('chrome', 'chromium')", dedup_keys=("origin_url", "username_value"), coalesce_map=_bl_coal)
            safe_sync_table("parsed_browser_logins", "parsed_edge_logins", "LOWER(COALESCE(browser, '')) LIKE '%edge%'", dedup_keys=("origin_url", "username_value"), coalesce_map=_bl_coal)
            safe_sync_table("parsed_browser_logins", "parsed_brave_logins", "LOWER(COALESCE(browser, '')) LIKE '%brave%'", dedup_keys=("origin_url", "username_value"), coalesce_map=_bl_coal)
            safe_sync_table("parsed_browser_logins", "parsed_firefox_logins", "LOWER(COALESCE(browser, '')) LIKE '%firefox%'", dedup_keys=("origin_url", "username_value"), coalesce_map=_bl_coal)

            # Explicitly purge legacy internal combined browser entries from artifact_registry
            try:
                cursor.execute("""
                    DELETE FROM artifact_registry
                    WHERE artifact_id IN ('browser_history', 'browser_downloads', 'browser_logins')
                       OR table_name IN ('parsed_browser_history', 'parsed_browser_downloads', 'parsed_browser_logins');
                """)
            except Exception:
                pass

            # 4. Chat Messages Sync
            safe_sync_table("parsed_chat_messages", "parsed_teams_messages", "LOWER(COALESCE(app_name, '')) LIKE '%team%'")
            safe_sync_table("parsed_chat_messages", "parsed_discord_messages", "LOWER(COALESCE(app_name, '')) LIKE '%discord%'")
            safe_sync_table("parsed_chat_messages", "parsed_slack_messages", "LOWER(COALESCE(app_name, '')) LIKE '%slack%'")
            safe_sync_table("parsed_chat_messages", "parsed_skype_messages", "LOWER(COALESCE(app_name, '')) LIKE '%skype%'")
            safe_sync_table("parsed_chat_messages", "parsed_whatsapp_messages", "LOWER(COALESCE(app_name, '')) LIKE '%whatsapp%'")
            safe_sync_table("parsed_chat_messages", "parsed_telegram_messages", "LOWER(COALESCE(app_name, '')) LIKE '%telegram%'")

            # 5. Cloud Synced Files Sync
            safe_sync_table("parsed_cloud_files", "parsed_onedrive_files", "LOWER(COALESCE(cloud_provider, '')) LIKE '%onedrive%'")
            safe_sync_table("parsed_cloud_files", "parsed_gdrive_files", "LOWER(COALESCE(cloud_provider, '')) LIKE '%google%' OR LOWER(COALESCE(cloud_provider, '')) LIKE '%gdrive%'")
            safe_sync_table("parsed_cloud_files", "parsed_dropbox_files", "LOWER(COALESCE(cloud_provider, '')) LIKE '%dropbox%'")

            # 6. Emails Sync
            safe_sync_table("parsed_emails", "parsed_outlook_emails", "LOWER(COALESCE(email_format, '')) IN ('pst', 'ost', 'msg', 'outlook')")
            safe_sync_table("parsed_emails", "parsed_mbox_emails", "LOWER(COALESCE(email_format, '')) IN ('mbox', 'thunderbird')")
            safe_sync_table("parsed_emails", "parsed_winmail_messages", "LOWER(COALESCE(email_format, '')) IN ('eml', 'winmail', 'windows mail')")

            # 7. OCR Results Sync (artifact_ocr_results <-> media_ocr_results without duplicating _row_id/scanned_at)
            safe_sync_table("artifact_ocr_results", "media_ocr_results", "1=1", exclude_cols=("_row_id", "scanned_at"))
            safe_sync_table("media_ocr_results", "artifact_ocr_results", "1=1", exclude_cols=("_row_id", "scanned_at"))

            # 8. Media Pictures & Videos Sync (NEVER delete existing rows when parsed_media_exif is empty!)
            if "parsed_media_exif" in tables_in_db:
                exif_cnt = cursor.execute("SELECT COUNT(*) FROM parsed_media_exif;").fetchone()[0] or 0
                if exif_cnt > 0:
                    exif_cols = [r[1] for r in cursor.execute("PRAGMA table_info(parsed_media_exif);").fetchall()]
                    has_pos = "gps_position" in exif_cols
                    has_coord = "gps_coordinates" in exif_cols
                    pos_expr = "gps_position" if has_pos else ("gps_coordinates" if has_coord else "CAST(NULL AS VARCHAR)")
                    coord_expr = "gps_coordinates" if has_coord else ("gps_position" if has_pos else "CAST(NULL AS VARCHAR)")
                    has_lat = "latitude" in exif_cols
                    has_lon = "longitude" in exif_cols
                    lat_expr = "latitude" if has_lat else ("gps_latitude" if "gps_latitude" in exif_cols else "CAST(NULL AS DOUBLE)")
                    lon_expr = "longitude" if has_lon else ("gps_longitude" if "gps_longitude" in exif_cols else "CAST(NULL AS DOUBLE)")
                    has_width = "image_width" in exif_cols
                    has_height = "image_height" in exif_cols
                    w_expr = "image_width" if has_width else ("width" if "width" in exif_cols else "CAST(NULL AS INTEGER)")
                    h_expr = "image_height" if has_height else ("height" if "height" in exif_cols else "CAST(NULL AS INTEGER)")
                    has_raw = "raw_metadata" in exif_cols
                    raw_expr = "raw_metadata" if has_raw else "CAST(NULL AS VARCHAR)"
                    has_src = "source_file" in exif_cols
                    src_expr = "source_file" if has_src else "CAST(NULL AS VARCHAR)"

                    if "parsed_media_pictures" in tables_in_db:
                        max_pic_id = cursor.execute("SELECT COALESCE(MAX(_row_id), 0) FROM parsed_media_pictures;").fetchone()[0] or 0
                        cursor.execute(f"""
                            INSERT INTO parsed_media_pictures (
                                _row_id, file_path, file_name, file_type, file_size_bytes, sha256, camera_make, camera_model,
                                datetime_original, software, image_width, image_height, latitude, longitude, gps_position, gps_coordinates,
                                raw_metadata, source_file
                            )
                            SELECT
                                {int(max_pic_id)} + row_number() OVER (),
                                file_path, file_name, file_type, file_size_bytes, sha256, camera_make, camera_model,
                                datetime_original, software, image_width, image_height, latitude, longitude, gps_position, gps_coordinates,
                                raw_metadata, source_file
                            FROM (
                                SELECT
                                    file_path, file_name, file_type, file_size_bytes, sha256, camera_make, camera_model,
                                    datetime_original, software, {w_expr} AS image_width, {h_expr} AS image_height,
                                    {lat_expr} AS latitude, {lon_expr} AS longitude, {pos_expr} AS gps_position, {coord_expr} AS gps_coordinates,
                                    {raw_expr} AS raw_metadata, {src_expr} AS source_file
                                FROM parsed_media_exif
                                WHERE LOWER(COALESCE(file_type, '')) IN ('jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'tiff', 'heic', 'image')
                                EXCEPT SELECT
                                    file_path, file_name, file_type, file_size_bytes, sha256, camera_make, camera_model,
                                    datetime_original, software, image_width, image_height, latitude, longitude, gps_position, gps_coordinates,
                                    raw_metadata, source_file
                                FROM parsed_media_pictures
                            ) _pic_diff;
                        """)

                    if "parsed_media_videos" in tables_in_db:
                        max_vid_id = cursor.execute("SELECT COALESCE(MAX(_row_id), 0) FROM parsed_media_videos;").fetchone()[0] or 0
                        has_dur = "duration_seconds" in exif_cols
                        dur_expr = "duration_seconds" if has_dur else "CAST(NULL AS DOUBLE)"
                        cursor.execute(f"""
                            INSERT INTO parsed_media_videos (
                                _row_id, file_path, file_name, file_type, file_size_bytes, sha256, datetime_original,
                                duration_seconds, width, height, raw_metadata, source_file
                            )
                            SELECT
                                {int(max_vid_id)} + row_number() OVER (),
                                file_path, file_name, file_type, file_size_bytes, sha256, datetime_original,
                                duration_seconds, width, height, raw_metadata, source_file
                            FROM (
                                SELECT
                                    file_path, file_name, file_type, file_size_bytes, sha256, datetime_original,
                                    {dur_expr} AS duration_seconds, {w_expr} AS width, {h_expr} AS height,
                                    {raw_expr} AS raw_metadata, {src_expr} AS source_file
                                FROM parsed_media_exif
                                WHERE LOWER(COALESCE(file_type, '')) IN ('mp4', 'mov', 'avi', 'mkv', 'wmv', 'flv', 'video')
                                EXCEPT SELECT
                                    file_path, file_name, file_type, file_size_bytes, sha256, datetime_original,
                                    duration_seconds, width, height, raw_metadata, source_file
                                FROM parsed_media_videos
                            ) _vid_diff;
                        """)

            # 9. Dynamic EVTX Views
            register_evtx_granular_views(conn, case_id=case_id, _in_tx=started_tx or _in_tx)

            if started_tx:
                cursor.execute("COMMIT;")
                started_tx = False

        except Exception as sync_ex:
            if started_tx:
                try:
                    conn.cursor().execute("ROLLBACK;")
                except Exception:
                    pass
            print(f"[Schema] Warning during granular artifacts synchronization: {sync_ex}")


def sync_artifact_registry_counts(conn: duckdb.DuckDBPyConnection, case_id: Optional[str] = None) -> int:
    """
    Synchronizes virtual views, granular tables, and live DuckDB row counts into artifact_registry.
    Ensures artifact_registry accurately reflects real rows in case.duckdb across all 10 canonical categories
    without destructively wiping refined results, keyword hits, OCR, documents, or combined artifacts.
    """
    with _acquire_case_lock(case_id):
        cursor = conn.cursor()
        tables_in_db = set(
            r[0]
            for r in cursor.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
            ).fetchall()
        )
        tables_in_db_lower = {t.lower() for t in tables_in_db}

        # 1. Ensure unified view_keyword_hits & keyword_hits alias exist under 'REFINED RESULTS'
        if "parsed_keyword_hits" in tables_in_db:
            try:
                kw_cnt = cursor.execute("SELECT COUNT(*) FROM parsed_keyword_hits;").fetchone()[0] or 0
                cursor.execute("BEGIN TRANSACTION;")
                try:
                    cursor.execute("""
                        CREATE OR REPLACE VIEW view_keyword_hits AS
                        SELECT * FROM parsed_keyword_hits ORDER BY _row_id ASC;
                    """)
                    cursor.execute("CREATE OR REPLACE VIEW keyword_hits AS SELECT * FROM view_keyword_hits;")
                    cursor.execute(
                        """
                        INSERT INTO artifact_registry (
                            artifact_id, category, display_name, table_name, source_tool, row_count, last_updated
                        ) VALUES ('keyword_hits', 'REFINED RESULTS', 'Keyword Hits', 'view_keyword_hits', 'KeywordScanner', ?, now())
                        ON CONFLICT (artifact_id) DO UPDATE SET
                            category = 'REFINED RESULTS',
                            display_name = 'Keyword Hits',
                            table_name = 'view_keyword_hits',
                            row_count = EXCLUDED.row_count,
                            last_updated = now();
                        """,
                        [kw_cnt],
                    )
                    cursor.execute("COMMIT;")
                    tables_in_db.add("view_keyword_hits")
                    tables_in_db.add("keyword_hits")
                    tables_in_db_lower.add("view_keyword_hits")
                    tables_in_db_lower.add("keyword_hits")
                except Exception:
                    cursor.execute("ROLLBACK;")
                    raise
            except Exception as kw_ex:
                print(f"[Schema] Warning syncing view_keyword_hits: {kw_ex}")

        # 1b. Reconcile columns needed by catalog views ONLY when genuinely missing
        existing_cols = {
            (str(r[0]).lower(), str(r[1]).lower())
            for r in cursor.execute(
                "SELECT LOWER(table_name), LOWER(column_name) FROM information_schema.columns WHERE table_schema = 'main';"
            ).fetchall()
        }
        _view_compat_alters = (
            ("artifact_stinger_hits", "ALTER TABLE artifact_stinger_hits ADD COLUMN IF NOT EXISTS engine VARCHAR DEFAULT 'Trellix Stinger';"),
            ("artifact_yara_hits", "ALTER TABLE artifact_yara_hits ADD COLUMN IF NOT EXISTS severity VARCHAR;"),
            ("vfs_partitions", "ALTER TABLE vfs_partitions ADD COLUMN IF NOT EXISTS description VARCHAR;"),
            ("vfs_partitions", "ALTER TABLE vfs_partitions ADD COLUMN IF NOT EXISTS volume_label VARCHAR;"),
            ("parsed_autoruns", "ALTER TABLE parsed_autoruns ADD COLUMN IF NOT EXISTS entry_name VARCHAR;"),
            ("parsed_autoruns", "ALTER TABLE parsed_autoruns ADD COLUMN IF NOT EXISTS value_name VARCHAR;"),
            ("parsed_autoruns", "ALTER TABLE parsed_autoruns ADD COLUMN IF NOT EXISTS autorun_type VARCHAR;"),
            ("parsed_autoruns", "ALTER TABLE parsed_autoruns ADD COLUMN IF NOT EXISTS category VARCHAR;"),
            ("parsed_autoruns", "ALTER TABLE parsed_autoruns ADD COLUMN IF NOT EXISTS key_path VARCHAR;"),
            ("parsed_autoruns", "ALTER TABLE parsed_autoruns ADD COLUMN IF NOT EXISTS location VARCHAR;"),
            ("parsed_autoruns", "ALTER TABLE parsed_autoruns ADD COLUMN IF NOT EXISTS command VARCHAR;"),
            ("parsed_autoruns", "ALTER TABLE parsed_autoruns ADD COLUMN IF NOT EXISTS launch_string VARCHAR;"),
            ("parsed_autoruns", "ALTER TABLE parsed_autoruns ADD COLUMN IF NOT EXISTS image_path VARCHAR;"),
            ("parsed_autoruns", "ALTER TABLE parsed_autoruns ADD COLUMN IF NOT EXISTS username VARCHAR;"),
            ("parsed_autoruns", "ALTER TABLE parsed_autoruns ADD COLUMN IF NOT EXISTS last_modified_utc TIMESTAMP;"),
            ("parsed_autoruns", "ALTER TABLE parsed_autoruns ADD COLUMN IF NOT EXISTS last_write_utc TIMESTAMP;"),
            ("parsed_autoruns", "ALTER TABLE parsed_autoruns ADD COLUMN IF NOT EXISTS hive_path VARCHAR;"),
            ("parsed_autoruns", "ALTER TABLE parsed_autoruns ADD COLUMN IF NOT EXISTS source_file VARCHAR;"),
            ("parsed_bam_dam", "ALTER TABLE parsed_bam_dam ADD COLUMN IF NOT EXISTS service_type VARCHAR;"),
            ("parsed_bam_dam", "ALTER TABLE parsed_bam_dam ADD COLUMN IF NOT EXISTS executable_path VARCHAR;"),
            ("parsed_bam_dam", "ALTER TABLE parsed_bam_dam ADD COLUMN IF NOT EXISTS app_name VARCHAR;"),
            ("parsed_bam_dam", "ALTER TABLE parsed_bam_dam ADD COLUMN IF NOT EXISTS user_sid VARCHAR;"),
            ("parsed_bam_dam", "ALTER TABLE parsed_bam_dam ADD COLUMN IF NOT EXISTS username VARCHAR;"),
            ("parsed_bam_dam", "ALTER TABLE parsed_bam_dam ADD COLUMN IF NOT EXISTS key_path VARCHAR;"),
            ("parsed_bam_dam", "ALTER TABLE parsed_bam_dam ADD COLUMN IF NOT EXISTS last_execution_utc TIMESTAMP;"),
            ("parsed_bam_dam", "ALTER TABLE parsed_bam_dam ADD COLUMN IF NOT EXISTS execution_time_utc TIMESTAMP;"),
            ("parsed_bam_dam", "ALTER TABLE parsed_bam_dam ADD COLUMN IF NOT EXISTS hive_path VARCHAR;"),
            ("parsed_bam_dam", "ALTER TABLE parsed_bam_dam ADD COLUMN IF NOT EXISTS source_file VARCHAR;"),
            ("parsed_userassist", "ALTER TABLE parsed_userassist ADD COLUMN IF NOT EXISTS program_path VARCHAR;"),
            ("parsed_userassist", "ALTER TABLE parsed_userassist ADD COLUMN IF NOT EXISTS rot13_name VARCHAR;"),
            ("parsed_userassist", "ALTER TABLE parsed_userassist ADD COLUMN IF NOT EXISTS guid VARCHAR;"),
            ("parsed_userassist", "ALTER TABLE parsed_userassist ADD COLUMN IF NOT EXISTS run_count INTEGER;"),
            ("parsed_userassist", "ALTER TABLE parsed_userassist ADD COLUMN IF NOT EXISTS focus_count INTEGER;"),
            ("parsed_userassist", "ALTER TABLE parsed_userassist ADD COLUMN IF NOT EXISTS focus_time_ms BIGINT;"),
            ("parsed_userassist", "ALTER TABLE parsed_userassist ADD COLUMN IF NOT EXISTS username VARCHAR;"),
            ("parsed_userassist", "ALTER TABLE parsed_userassist ADD COLUMN IF NOT EXISTS key_path VARCHAR;"),
            ("parsed_userassist", "ALTER TABLE parsed_userassist ADD COLUMN IF NOT EXISTS last_executed_utc TIMESTAMP;"),
            ("parsed_userassist", "ALTER TABLE parsed_userassist ADD COLUMN IF NOT EXISTS last_run_utc TIMESTAMP;"),
            ("parsed_userassist", "ALTER TABLE parsed_userassist ADD COLUMN IF NOT EXISTS hive_path VARCHAR;"),
            ("parsed_userassist", "ALTER TABLE parsed_userassist ADD COLUMN IF NOT EXISTS source_file VARCHAR;"),
            ("raw_recmd", "ALTER TABLE raw_recmd ADD COLUMN IF NOT EXISTS ValueData2 VARCHAR;"),
            ("raw_recmd", "ALTER TABLE raw_recmd ADD COLUMN IF NOT EXISTS Description VARCHAR;"),
        )
        missing_compat_alters: List[str] = []
        for req_tbl, alter_stmt in _view_compat_alters:
            if req_tbl.lower() in tables_in_db_lower:
                parsed_tc = _parse_alter_add_col(alter_stmt)
                if parsed_tc is None or parsed_tc not in existing_cols:
                    missing_compat_alters.append(alter_stmt)
        if missing_compat_alters:
            try:
                cursor.execute("BEGIN TRANSACTION;")
                for alter_stmt in missing_compat_alters:
                    cursor.execute(alter_stmt)
                cursor.execute("COMMIT;")
            except Exception:
                try:
                    cursor.execute("ROLLBACK;")
                except Exception:
                    pass
                for alter_stmt in missing_compat_alters:
                    try:
                        cursor.execute(alter_stmt)
                    except Exception:
                        pass

        # 2. Refresh non-refined virtual views from MASTER_ARTIFACT_CATALOG in a single transaction
        views_to_refresh: List[Tuple[str, str]] = []
        for entry in MASTER_ARTIFACT_CATALOG:
            vname = entry["table_name"]
            if not vname.startswith("view_") or vname == "view_keyword_hits":
                continue
            if vname.startswith("view_refined_") and vname in tables_in_db:
                continue
            if vname == "view_all_malware_detections" and vname in tables_in_db:
                if (
                    ("view_all_malware_detections", "threat_name") in existing_cols
                    and ("view_all_malware_detections", "severity") in existing_cols
                    and ("view_all_malware_detections", "_row_id") in existing_cols
                ):
                    continue
            views_to_refresh.append((vname, entry["ddl"]))

        if views_to_refresh:
            try:
                cursor.execute("BEGIN TRANSACTION;")
                for vname, vddl in views_to_refresh:
                    cursor.execute(vddl)
                cursor.execute("COMMIT;")
                for vname, _ in views_to_refresh:
                    tables_in_db.add(vname)
            except Exception:
                try:
                    cursor.execute("ROLLBACK;")
                except Exception:
                    pass
                for vname, vddl in views_to_refresh:
                    try:
                        cursor.execute(vddl)
                        tables_in_db.add(vname)
                    except Exception as ex:
                        print(f"[Schema] Warning refreshing view {vname}: {ex}")

        # 3. Granular sub-tables sync & dynamic EVTX views (sync_granular_artifacts runs register_evtx_granular_views inside its tx)
        try:
            sync_granular_artifacts(conn, case_id=case_id)
        except Exception as s_ex:
            print(f"[Schema] Warning in sync_granular_artifacts: {s_ex}")

        # Refresh tables_in_db once after view/granular updates
        tables_in_db = set(
            r[0]
            for r in cursor.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
            ).fetchall()
        )

        # Pre-compute catalog + existing registry + uncataloged table counts in batched UNION ALL reads
        existing_registered = cursor.execute("SELECT artifact_id, table_name FROM artifact_registry;").fetchall()
        catalog_rows = [
            (
                entry["artifact_id"],
                entry["category"],
                entry["display_name"],
                entry["table_name"],
                entry["source_tool"],
            )
            for entry in MASTER_ARTIFACT_CATALOG
        ]
        internal_tables = {
            "parsed_browser_history",
            "parsed_browser_downloads",
            "parsed_browser_logins",
            "parsed_media_exif",
            "parsed_documents_metadata",
            "parsed_text_documents",
            "parsed_keyword_hits",
            "artifact_ocr_results",
        }
        internal_artifact_ids = {
            "browser_history",
            "browser_downloads",
            "browser_logins",
            "media_exif",
            "documents_metadata",
            "ocr_extracted_text",
            "ocr_results",
        }

        reg_map: Dict[str, str] = {str(aid): str(tbl) for aid, tbl in existing_registered}
        for aid, _cat, _disp, tbl, _src in catalog_rows:
            reg_map[aid] = tbl
        for aid in list(reg_map.keys()):
            if aid in internal_artifact_ids or reg_map[aid] in internal_tables:
                reg_map.pop(aid, None)

        registered_tables = set(reg_map.values())
        uncataloged_candidates = [
            tname
            for tname in sorted(tables_in_db)
            if tname not in internal_tables
            and tname not in registered_tables
            and (tname.startswith("raw_") or tname.startswith("parsed_"))
        ]

        tables_to_count = [
            t for t in list(dict.fromkeys(list(reg_map.values()) + uncataloged_candidates)) if t in tables_in_db
        ]
        live_counts = _batch_count_tables(cursor, tables_to_count, chunk_size=25)

        # 4, 5, 6, 7. Apply all artifact_registry upserts, category standardizations, and count updates in ONE transaction
        tx_open = False
        try:
            cursor.execute("BEGIN TRANSACTION;")
            tx_open = True

            if catalog_rows:
                cursor.executemany(
                    """
                    INSERT INTO artifact_registry (
                        artifact_id, category, display_name, table_name, source_tool, row_count, last_updated
                    ) VALUES (?, ?, ?, ?, ?, 0, CURRENT_TIMESTAMP)
                    ON CONFLICT (artifact_id) DO UPDATE SET
                        category = EXCLUDED.category,
                        display_name = EXCLUDED.display_name,
                        table_name = EXCLUDED.table_name,
                        source_tool = EXCLUDED.source_tool;
                    """,
                    catalog_rows,
                )

            cursor.execute("""
                DELETE FROM artifact_registry
                WHERE artifact_id IN ('browser_history', 'browser_downloads', 'browser_logins', 'media_exif', 'documents_metadata', 'ocr_extracted_text', 'ocr_results')
                   OR table_name IN ('parsed_browser_history', 'parsed_browser_downloads', 'parsed_browser_logins', 'parsed_media_exif', 'parsed_documents_metadata', 'artifact_ocr_results');

                UPDATE artifact_registry SET category = 'EVENT LOGS'
                WHERE category IN ('Event Logs', 'EVENT LOGS') OR table_name = 'raw_evtx' OR table_name LIKE 'view_evtx_%';

                UPDATE artifact_registry SET category = 'OPERATING SYSTEM'
                WHERE (category IN ('Program Execution', 'File System', 'Registry & OS', 'Network & SRUM', 'USB & External Devices', 'Operating System', 'USB & EXTERNAL DEVICES', 'OPERATING SYSTEM', 'Database & SQLite')
                       OR artifact_id IN ('view_usb_devices', 'view_autoruns', 'view_bam_dam', 'view_userassist'))
                  AND table_name != 'raw_evtx' AND table_name NOT LIKE 'view_evtx_%';

                UPDATE artifact_registry SET category = 'WEB RELATED'
                WHERE category IN ('Web Browsers', 'Web Related', 'WEB RELATED');

                UPDATE artifact_registry SET category = 'CHAT'
                WHERE category IN ('Chat & Collaboration', 'Chat', 'CHAT');

                UPDATE artifact_registry SET category = 'EMAIL & CALENDAR'
                WHERE UPPER(TRIM(COALESCE(category, ''))) IN ('EMAIL', 'EMAILS', 'MAIL', 'EMAIL & CALENDAR');

                UPDATE artifact_registry SET category = 'CLOUD'
                WHERE category IN ('Cloud Storage', 'Cloud', 'CLOUD');

                UPDATE artifact_registry SET category = 'MEDIA'
                WHERE category IN ('Media & Pictures', 'Media & OCR', 'Media', 'MEDIA');

                UPDATE artifact_registry SET category = 'DOCUMENTS'
                WHERE category IN ('Documents', 'Documents & Metadata', 'DOCUMENTS');

                UPDATE artifact_registry SET category = 'MALWARE & YARA'
                WHERE category IN ('Malware & Threat Hunting', 'Malware & YARA', 'MALWARE & YARA');

                UPDATE artifact_registry SET category = 'REFINED RESULTS'
                WHERE category IN ('Refined Results', 'KEYWORD HITS', 'Keyword Hits', 'REFINED RESULTS')
                   OR artifact_id = 'keyword_hits';
            """)

            registered_after = cursor.execute("SELECT artifact_id, table_name FROM artifact_registry;").fetchall()
            count_updates = [
                [int(live_counts.get(tname, 0)) if tname in tables_in_db else 0, art_id]
                for art_id, tname in registered_after
            ]
            if count_updates:
                cursor.executemany(
                    "UPDATE artifact_registry SET row_count = ?, last_updated = now() WHERE artifact_id = ?;",
                    count_updates,
                )

            uncataloged_inserts: List[List[Any]] = []
            for tname in uncataloged_candidates:
                cnt = int(live_counts.get(tname, 0))
                if cnt > 0:
                    cat = "OPERATING SYSTEM"
                    src = "EZ Tools / Parser"
                    if "evtx" in tname:
                        cat = "EVENT LOGS"
                        src = "EvtxECmd.exe"
                    elif "srum" in tname:
                        cat = "OPERATING SYSTEM"
                        src = "SrumECmd.exe"
                    elif "pecmd" in tname:
                        cat = "OPERATING SYSTEM"
                        src = "PECmd.exe"
                    elif "hindsight" in tname or "chrome" in tname or "edge" in tname or "brave" in tname or "firefox" in tname:
                        cat = "WEB RELATED"
                    elif "email" in tname or "mbox" in tname or "outlook" in tname or "winmail" in tname:
                        cat = "EMAIL & CALENDAR"
                    elif "bulk_extractor" in tname:
                        cat = "REFINED RESULTS"
                    disp = tname.replace("raw_", "").replace("parsed_", "").replace("_", " ").title()
                    uncataloged_inserts.append([tname, cat, disp, tname, src, cnt])

            if uncataloged_inserts:
                cursor.executemany(
                    """
                    INSERT INTO artifact_registry (artifact_id, category, display_name, table_name, source_tool, row_count, last_updated)
                    VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT (artifact_id) DO UPDATE SET row_count = EXCLUDED.row_count;
                    """,
                    uncataloged_inserts,
                )

            cursor.execute("COMMIT;")
            tx_open = False
        except Exception as std_ex:
            if tx_open:
                try:
                    cursor.execute("ROLLBACK;")
                except Exception:
                    pass
            print(f"[Schema] Warning synchronizing artifact_registry transaction: {std_ex}")

        total = cursor.execute("SELECT COALESCE(SUM(row_count), 0) FROM artifact_registry WHERE row_count > 0;").fetchone()[0]
        return int(total)


def init_schema(conn: duckdb.DuckDBPyConnection, case_id: Optional[str] = None) -> None:
    """
    Execute DDL on DuckDB connection to ensure all core tables, migrations, indexes, and sequences exist,
    pre-populates artifact_registry across all 10 canonical WFT categories,
    and creates their schema tables/views so queries never fail.
    """
    with _acquire_case_lock(case_id):
        cursor = conn.cursor()
        had_existing_tables = bool(
            cursor.execute(
                "SELECT 1 FROM information_schema.tables WHERE table_schema = 'main' LIMIT 1;"
            ).fetchone()
        )

        # 1 & 2. Execute core schema DDL and Pass 1 catalog table DDLs in a single transaction
        table_entries = [e for e in MASTER_ARTIFACT_CATALOG if not e["table_name"].startswith("view_")]
        try:
            cursor.execute("BEGIN TRANSACTION;")
            cursor.execute(CORE_SCHEMA_SQL)
            for entry in table_entries:
                cursor.execute(entry["ddl"])
            cursor.execute("COMMIT;")
        except Exception:
            try:
                cursor.execute("ROLLBACK;")
            except Exception:
                pass
            cursor.execute(CORE_SCHEMA_SQL)
            for entry in table_entries:
                try:
                    cursor.execute(entry["ddl"])
                except Exception as ddl_ex:
                    print(f"[Schema] Warning executing DDL for table {entry['table_name']}: {ddl_ex}")

        # 3. Safe schema migrations for existing databases (run ALTER TABLE only for genuinely missing columns)
        existing_cols = {
            (str(r[0]).lower(), str(r[1]).lower())
            for r in cursor.execute(
                "SELECT LOWER(table_name), LOWER(column_name) FROM information_schema.columns WHERE table_schema = 'main';"
            ).fetchall()
        }
        migration_statements = [
            "ALTER TABLE master_timeline ADD COLUMN IF NOT EXISTS macb VARCHAR DEFAULT '';",
            "ALTER TABLE case_keywords ADD COLUMN IF NOT EXISTS is_regex BOOLEAN DEFAULT FALSE;",
            "ALTER TABLE case_keywords ADD COLUMN IF NOT EXISTS is_case_sensitive BOOLEAN DEFAULT FALSE;",
            "ALTER TABLE case_keywords ADD COLUMN IF NOT EXISTS case_sensitive BOOLEAN DEFAULT FALSE;",
            "ALTER TABLE case_keywords ADD COLUMN IF NOT EXISTS category VARCHAR DEFAULT 'General';",
            "ALTER TABLE case_keywords ADD COLUMN IF NOT EXISTS source_file VARCHAR;",
            "ALTER TABLE case_keywords ADD COLUMN IF NOT EXISTS hit_count BIGINT DEFAULT 0;",
            "ALTER TABLE case_keywords ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;",
            "ALTER TABLE parsed_keyword_hits ADD COLUMN IF NOT EXISTS keyword_id VARCHAR;",
            "ALTER TABLE parsed_keyword_hits ADD COLUMN IF NOT EXISTS is_regex BOOLEAN DEFAULT FALSE;",
            "ALTER TABLE parsed_keyword_hits ADD COLUMN IF NOT EXISTS is_case_sensitive BOOLEAN DEFAULT FALSE;",
            "ALTER TABLE parsed_keyword_hits ADD COLUMN IF NOT EXISTS matched_column VARCHAR;",
            "ALTER TABLE parsed_keyword_hits ADD COLUMN IF NOT EXISTS match_offset BIGINT;",
            "ALTER TABLE parsed_keyword_hits ADD COLUMN IF NOT EXISTS encoding VARCHAR;",
            "ALTER TABLE raw_mft ADD COLUMN IF NOT EXISTS IsDirectory BOOLEAN;",
            "ALTER TABLE raw_mft ADD COLUMN IF NOT EXISTS LastAccess0x30 TIMESTAMP;",
            "ALTER TABLE raw_mft ADD COLUMN IF NOT EXISTS LastRecordChange0x30 TIMESTAMP;",
            "ALTER TABLE parsed_firefox_cookies ADD COLUMN IF NOT EXISTS host_key VARCHAR;",
            "ALTER TABLE parsed_firefox_cookies ADD COLUMN IF NOT EXISTS creation_utc TIMESTAMP;",
            "ALTER TABLE parsed_firefox_cookies ADD COLUMN IF NOT EXISTS expires_utc TIMESTAMP;",
            "ALTER TABLE parsed_firefox_cookies ADD COLUMN IF NOT EXISTS last_access_utc TIMESTAMP;",
            "ALTER TABLE parsed_firefox_bookmarks ADD COLUMN IF NOT EXISTS date_modified TIMESTAMP;",
            "ALTER TABLE artifact_yara_hits ADD COLUMN IF NOT EXISTS severity VARCHAR;",
            "ALTER TABLE artifact_yara_hits ADD COLUMN IF NOT EXISTS category VARCHAR;",
            "ALTER TABLE artifact_yara_hits ADD COLUMN IF NOT EXISTS description VARCHAR;",
            "ALTER TABLE artifact_yara_hits ADD COLUMN IF NOT EXISTS mitre_attack VARCHAR;",
            "ALTER TABLE artifact_stinger_hits ADD COLUMN IF NOT EXISTS engine VARCHAR DEFAULT 'Trellix Stinger';",
            "ALTER TABLE raw_evtx ADD COLUMN IF NOT EXISTS PayloadData2 VARCHAR;",
            "ALTER TABLE raw_evtx ADD COLUMN IF NOT EXISTS PayloadData3 VARCHAR;",
            "ALTER TABLE raw_evtx ADD COLUMN IF NOT EXISTS PayloadData4 VARCHAR;",
            "ALTER TABLE raw_evtx ADD COLUMN IF NOT EXISTS PayloadData5 VARCHAR;",
            "ALTER TABLE raw_evtx ADD COLUMN IF NOT EXISTS PayloadData6 VARCHAR;",
            "ALTER TABLE raw_evtx ADD COLUMN IF NOT EXISTS Payload VARCHAR;",
            "ALTER TABLE vfs_partitions ADD COLUMN IF NOT EXISTS part_index INTEGER;",
            "ALTER TABLE vfs_partitions ADD COLUMN IF NOT EXISTS label VARCHAR;",
            "ALTER TABLE vfs_partitions ADD COLUMN IF NOT EXISTS description VARCHAR;",
            "ALTER TABLE vfs_partitions ADD COLUMN IF NOT EXISTS fs_type VARCHAR;",
            "ALTER TABLE vfs_partitions ADD COLUMN IF NOT EXISTS offset_bytes BIGINT;",
            "ALTER TABLE vfs_partitions ADD COLUMN IF NOT EXISTS size_bytes BIGINT;",
            "ALTER TABLE vfs_partitions ADD COLUMN IF NOT EXISTS volume_serial VARCHAR;",
            "ALTER TABLE vfs_partitions ADD COLUMN IF NOT EXISTS is_boot BOOLEAN;",
            "ALTER TABLE vfs_files ADD COLUMN IF NOT EXISTS part_index INTEGER;",
            "ALTER TABLE vfs_files ADD COLUMN IF NOT EXISTS vfs_path VARCHAR;",
            "ALTER TABLE vfs_files ADD COLUMN IF NOT EXISTS staged_rel_path VARCHAR;",
            "ALTER TABLE vfs_files ADD COLUMN IF NOT EXISTS file_name VARCHAR;",
            "ALTER TABLE vfs_files ADD COLUMN IF NOT EXISTS parent_path VARCHAR;",
            "ALTER TABLE vfs_files ADD COLUMN IF NOT EXISTS size_bytes BIGINT;",
            "ALTER TABLE vfs_files ADD COLUMN IF NOT EXISTS is_dir BOOLEAN;",
            "ALTER TABLE vfs_files ADD COLUMN IF NOT EXISTS is_deleted BOOLEAN;",
            "ALTER TABLE vfs_files ADD COLUMN IF NOT EXISTS si_created TIMESTAMP;",
            "ALTER TABLE vfs_files ADD COLUMN IF NOT EXISTS si_modified TIMESTAMP;",
            "ALTER TABLE vfs_files ADD COLUMN IF NOT EXISTS si_accessed TIMESTAMP;",
            "ALTER TABLE vfs_files ADD COLUMN IF NOT EXISTS si_changed TIMESTAMP;",
            "ALTER TABLE vfs_files ADD COLUMN IF NOT EXISTS fn_created TIMESTAMP;",
            "ALTER TABLE vfs_files ADD COLUMN IF NOT EXISTS fn_modified TIMESTAMP;",
            "ALTER TABLE vfs_files ADD COLUMN IF NOT EXISTS fn_accessed TIMESTAMP;",
            "ALTER TABLE vfs_files ADD COLUMN IF NOT EXISTS fn_changed TIMESTAMP;",
            "ALTER TABLE vfs_files ADD COLUMN IF NOT EXISTS mft_entry BIGINT;",
            "ALTER TABLE vfs_shadow_copies ADD COLUMN IF NOT EXISTS vss_index INTEGER;",
            "ALTER TABLE vfs_shadow_copies ADD COLUMN IF NOT EXISTS part_index INTEGER;",
            "ALTER TABLE vfs_shadow_copies ADD COLUMN IF NOT EXISTS store_id VARCHAR;",
            "ALTER TABLE vfs_shadow_copies ADD COLUMN IF NOT EXISTS creation_time TIMESTAMP;",
            "ALTER TABLE vfs_shadow_copies ADD COLUMN IF NOT EXISTS size_bytes BIGINT;",
            "ALTER TABLE vfs_shadow_copies ADD COLUMN IF NOT EXISTS staged_prefix VARCHAR;",
            "ALTER TABLE vfs_shadow_copies ADD COLUMN IF NOT EXISTS files_staged INTEGER;",
            "ALTER TABLE vfs_shadow_copies ADD COLUMN IF NOT EXISTS status VARCHAR;",
            "ALTER TABLE parsed_carved_files ADD COLUMN IF NOT EXISTS offset_bytes BIGINT;",
            "ALTER TABLE parsed_carved_files ADD COLUMN IF NOT EXISTS carved_rel_path VARCHAR;",
            "ALTER TABLE parsed_carved_files ADD COLUMN IF NOT EXISTS source_region VARCHAR;",
            "ALTER TABLE parsed_carved_files ADD COLUMN IF NOT EXISTS header_sig VARCHAR;",
            "ALTER TABLE parsed_carved_files ADD COLUMN IF NOT EXISTS validated BOOLEAN;",
            "ALTER TABLE media_ocr_results ADD COLUMN IF NOT EXISTS ocr_text VARCHAR;",
            "ALTER TABLE media_ocr_results ADD COLUMN IF NOT EXISTS avg_confidence DOUBLE;",
            "ALTER TABLE media_ocr_results ADD COLUMN IF NOT EXISTS engine VARCHAR;",
            "ALTER TABLE media_ocr_results ADD COLUMN IF NOT EXISTS line_count INTEGER;",
            "ALTER TABLE media_ocr_results ADD COLUMN IF NOT EXISTS char_count INTEGER;",
            "ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS file_type VARCHAR;",
            "ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS extension VARCHAR;",
            "ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS file_size_bytes BIGINT;",
            "ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS created_time TIMESTAMP;",
            "ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS modified_time TIMESTAMP;",
            "ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS author VARCHAR;",
            "ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS title VARCHAR;",
            "ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS encoding VARCHAR;",
            "ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS line_count INTEGER;",
            "ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS word_count INTEGER;",
            "ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS content_preview VARCHAR;",
            "ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS text_preview VARCHAR;",
            "ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS char_count BIGINT;",
            "ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS last_modified_by VARCHAR;",
            "ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS embedded_links VARCHAR;",
            "ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS zone_id INTEGER;",
            "ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS zone_host_url VARCHAR;",
            "ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS zone_referrer_url VARCHAR;",
            "ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS host_url VARCHAR;",
            "ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS referrer_url VARCHAR;",
            "ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS sha256 VARCHAR;",
            "ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS source_file VARCHAR;",
            "ALTER TABLE parsed_notifications ADD COLUMN IF NOT EXISTS notification_id BIGINT;",
            "ALTER TABLE parsed_notifications ADD COLUMN IF NOT EXISTS notification_type VARCHAR;",
            "ALTER TABLE parsed_notifications ADD COLUMN IF NOT EXISTS payload VARCHAR;",
            "ALTER TABLE parsed_notifications ADD COLUMN IF NOT EXISTS arrival_time TIMESTAMP;",
            "ALTER TABLE parsed_notifications ADD COLUMN IF NOT EXISTS expiry_time TIMESTAMP;",
            "ALTER TABLE parsed_notifications ADD COLUMN IF NOT EXISTS timestamp_utc TIMESTAMP;",
            "ALTER TABLE parsed_notifications ADD COLUMN IF NOT EXISTS title VARCHAR;",
            "ALTER TABLE parsed_notifications ADD COLUMN IF NOT EXISTS body VARCHAR;",
            "ALTER TABLE parsed_notifications ADD COLUMN IF NOT EXISTS header VARCHAR;",
            "ALTER TABLE parsed_notifications ADD COLUMN IF NOT EXISTS action_url VARCHAR;",
            "ALTER TABLE parsed_notifications ADD COLUMN IF NOT EXISTS source_path VARCHAR;",
            "ALTER TABLE parsed_notifications ADD COLUMN IF NOT EXISTS source_file VARCHAR;",
            "ALTER TABLE file_enrichment ADD COLUMN IF NOT EXISTS _row_id BIGINT;",
            "ALTER TABLE file_enrichment ADD COLUMN IF NOT EXISTS enrichment_id BIGINT;",
            "ALTER TABLE file_enrichment ADD COLUMN IF NOT EXISTS md5 VARCHAR;",
            "ALTER TABLE file_enrichment ADD COLUMN IF NOT EXISTS shannon_entropy DOUBLE;",
            "ALTER TABLE file_enrichment ADD COLUMN IF NOT EXISTS is_pe BOOLEAN DEFAULT FALSE;",
            "ALTER TABLE file_enrichment ADD COLUMN IF NOT EXISTS pe_imphash VARCHAR;",
            "ALTER TABLE file_enrichment ADD COLUMN IF NOT EXISTS pe_compile_time TIMESTAMP;",
            "ALTER TABLE file_enrichment ADD COLUMN IF NOT EXISTS pe_sections_info VARCHAR;",
            "ALTER TABLE file_enrichment ADD COLUMN IF NOT EXISTS is_high_entropy BOOLEAN DEFAULT FALSE;",
            "ALTER TABLE file_enrichment ADD COLUMN IF NOT EXISTS yara_hit_count INTEGER DEFAULT 0;",
            "ALTER TABLE file_enrichment ADD COLUMN IF NOT EXISTS ioc_hit_count INTEGER DEFAULT 0;",
            "ALTER TABLE file_enrichment ADD COLUMN IF NOT EXISTS yara_rules_matched VARCHAR;",
            "ALTER TABLE file_enrichment ADD COLUMN IF NOT EXISTS yara_match_offsets VARCHAR;",
            "ALTER TABLE file_enrichment ADD COLUMN IF NOT EXISTS ocr_extracted_text VARCHAR;",
            "ALTER TABLE file_enrichment ADD COLUMN IF NOT EXISTS archive_parent VARCHAR;",
            "CREATE INDEX IF NOT EXISTS idx_mt_timestamp ON master_timeline(timestamp_utc);",
            "CREATE INDEX IF NOT EXISTS idx_mt_category ON master_timeline(category);",
            "CREATE INDEX IF NOT EXISTS idx_mt_source_table ON master_timeline(source_table);",
            "CREATE INDEX IF NOT EXISTS idx_ec_entity_val ON entity_connections(entity_value);",
            "CREATE INDEX IF NOT EXISTS idx_ec_source_table ON entity_connections(source_table);",
        ]
        existing_indexes = set()
        try:
            existing_indexes = {
                str(r[0]).lower()
                for r in cursor.execute("SELECT LOWER(index_name) FROM duckdb_indexes();").fetchall()
            }
        except Exception:
            existing_indexes = set()

        needed_migrations: List[str] = []
        for stmt in migration_statements:
            parsed_tc = _parse_alter_add_col(stmt)
            if parsed_tc is not None:
                if parsed_tc not in existing_cols:
                    needed_migrations.append(stmt)
            else:
                idx_m = re.search(r"CREATE\s+INDEX\s+IF\s+NOT\s+EXISTS\s+([A-Za-z0-9_]+)", stmt, re.IGNORECASE)
                if idx_m and idx_m.group(1).lower() in existing_indexes:
                    continue
                needed_migrations.append(stmt)

        if needed_migrations:
            try:
                cursor.execute("BEGIN TRANSACTION;")
                for stmt in needed_migrations:
                    cursor.execute(stmt)
                cursor.execute("COMMIT;")
            except Exception:
                try:
                    cursor.execute("ROLLBACK;")
                except Exception:
                    pass
                for stmt in needed_migrations:
                    try:
                        cursor.execute(stmt)
                    except Exception:
                        pass

        # 4 & 5. Pass 2 (create views) + Pass 3 (seed artifact_registry + canonical category cleanup) in ONE transaction
        view_entries = [e for e in MASTER_ARTIFACT_CATALOG if e["table_name"].startswith("view_")]
        seed_rows = [
            [
                entry["artifact_id"],
                entry["category"],
                entry["display_name"],
                entry["table_name"],
                entry["source_tool"],
            ]
            for entry in MASTER_ARTIFACT_CATALOG
        ]
        try:
            cursor.execute("BEGIN TRANSACTION;")
            for entry in view_entries:
                cursor.execute(entry["ddl"])
            cursor.executemany(
                """
                INSERT INTO artifact_registry (
                    artifact_id, category, display_name, table_name, source_tool, row_count, last_updated
                ) VALUES (?, ?, ?, ?, ?, 0, CURRENT_TIMESTAMP)
                ON CONFLICT (artifact_id) DO UPDATE SET
                    category = EXCLUDED.category,
                    display_name = EXCLUDED.display_name,
                    table_name = EXCLUDED.table_name,
                    source_tool = EXCLUDED.source_tool;
                """,
                seed_rows,
            )
            cursor.execute("""
                DELETE FROM artifact_registry
                WHERE artifact_id IN ('browser_history', 'browser_downloads', 'browser_logins', 'media_exif', 'documents_metadata', 'ocr_extracted_text', 'ocr_results')
                   OR table_name IN ('parsed_browser_history', 'parsed_browser_downloads', 'parsed_browser_logins', 'parsed_media_exif', 'parsed_documents_metadata', 'artifact_ocr_results');
            """)
            cursor.execute("COMMIT;")
        except Exception:
            try:
                cursor.execute("ROLLBACK;")
            except Exception:
                pass
            for entry in view_entries:
                try:
                    cursor.execute(entry["ddl"])
                except Exception as ddl_ex:
                    print(f"[Schema] Warning executing DDL for view {entry['table_name']}: {ddl_ex}")
            for s_row in seed_rows:
                try:
                    cursor.execute(
                        """
                        INSERT INTO artifact_registry (
                            artifact_id, category, display_name, table_name, source_tool, row_count, last_updated
                        ) VALUES (?, ?, ?, ?, ?, 0, CURRENT_TIMESTAMP)
                        ON CONFLICT (artifact_id) DO UPDATE SET
                            category = EXCLUDED.category,
                            display_name = EXCLUDED.display_name,
                            table_name = EXCLUDED.table_name,
                            source_tool = EXCLUDED.source_tool;
                        """,
                        s_row,
                    )
                except Exception as reg_ex:
                    print(f"[Schema] Warning populating artifact_registry for {s_row[0]}: {reg_ex}")

        # 6. Synchronize views, granular tables, and live row counts ONLY when DB has pre-existing tables or rows
        should_sync = had_existing_tables
        if should_sync:
            try:
                vfs_and_logs = (
                    cursor.execute(
                        "SELECT (SELECT COUNT(*) FROM vfs_files) + (SELECT COUNT(*) FROM processing_logs);"
                    ).fetchone()[0]
                    or 0
                )
                if vfs_and_logs == 0:
                    any_reg = (
                        cursor.execute(
                            "SELECT COALESCE(SUM(row_count), 0) FROM artifact_registry WHERE row_count > 0;"
                        ).fetchone()[0]
                        or 0
                    )
                    if any_reg == 0 and not had_existing_tables:
                        should_sync = False
            except Exception:
                should_sync = True
        if should_sync:
            sync_artifact_registry_counts(conn, case_id=case_id)


def verify_core_tables(conn: duckdb.DuckDBPyConnection, case_id: Optional[str] = None) -> List[str]:
    """
    Query the DuckDB information schema via a thread-local cursor and return a list of core tables that exist.
    """
    with _acquire_case_lock(case_id):
        cursor = conn.cursor()
        existing_tables = {
            row[0]
            for row in cursor.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
            ).fetchall()
        }
        return [t for t in CORE_TABLES if t in existing_tables]
