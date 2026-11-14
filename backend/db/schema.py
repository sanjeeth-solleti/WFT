"""
Windows Forensic Toolkit (WFT) DFIR Suite - DuckDB Schema Definitions & Master Artifact Catalog
Categorized into WFT's exact 10 canonical categories with granular
per-application, per-artifact tables and views, plus dynamic per-.evtx views under EVENT LOGS.
"""
import re
from typing import Any, Dict, List, Optional
import duckdb

CANONICAL_CATEGORIES: List[str] = [
    "REFINED RESULTS",
    "WEB RELATED",
    "CHAT",
    "EMAIL",
    "CLOUD",
    "MEDIA",
    "DOCUMENTS",
    "EVENT LOGS",
    "OPERATING SYSTEM",
    "MALWARE & YARA",
]
CANONICAL_WFT_CATEGORIES = CANONICAL_CATEGORIES

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
    "raw_regripper",
    "artifact_stinger_hits",
    "parsed_media_exif",
    "parsed_documents_metadata",
]

CORE_SCHEMA_SQL: str = """
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
    source_file VARCHAR
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
    file_path VARCHAR NOT NULL,
    file_name VARCHAR NOT NULL,
    extension VARCHAR,
    size_bytes BIGINT,
    sha256 VARCHAR,
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

-- 8. RapidOCR Extracted Text Table
CREATE TABLE IF NOT EXISTS artifact_ocr_results (
    _row_id BIGINT,
    file_path VARCHAR NOT NULL,
    file_name VARCHAR NOT NULL,
    dimensions VARCHAR,
    sha256 VARCHAR,
    extracted_text VARCHAR,
    confidence DOUBLE,
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 9. Case Keyword Search Table
CREATE TABLE IF NOT EXISTS case_keywords (
    keyword_id VARCHAR PRIMARY KEY,
    keyword VARCHAR UNIQUE,
    is_regex BOOLEAN DEFAULT FALSE,
    source_file VARCHAR,
    hit_count BIGINT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
    engine_version VARCHAR,
    details VARCHAR,
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 12. Parsed Media EXIF Metadata Table (Internal storage for granular views)
CREATE TABLE IF NOT EXISTS parsed_media_exif (
    _row_id BIGINT, file_path VARCHAR, file_name VARCHAR, file_type VARCHAR, file_size_bytes BIGINT, sha256 VARCHAR, camera_make VARCHAR, camera_model VARCHAR, datetime_original TIMESTAMP, software VARCHAR, image_width INTEGER, image_height INTEGER, duration_seconds DOUBLE, latitude DOUBLE, longitude DOUBLE, gps_position VARCHAR, gps_coordinates VARCHAR, raw_metadata VARCHAR, source_file VARCHAR
);

-- 13. Parsed Documents & Zone.Identifier Metadata Table (Internal storage for granular views)
CREATE TABLE IF NOT EXISTS parsed_documents_metadata (
    _row_id BIGINT, file_path VARCHAR, file_name VARCHAR, file_type VARCHAR, file_size_bytes BIGINT, title VARCHAR, author VARCHAR, last_modified_by VARCHAR, created_time TIMESTAMP, modified_time TIMESTAMP, page_count INTEGER, word_count INTEGER, has_macros BOOLEAN, embedded_links VARCHAR, zone_id INTEGER, zone_host_url VARCHAR, zone_referrer_url VARCHAR, host_url VARCHAR, referrer_url VARCHAR, sha256 VARCHAR, source_file VARCHAR
);

-- Auto-incrementing helper sequences
CREATE SEQUENCE IF NOT EXISTS seq_timeline_id START 1;
CREATE SEQUENCE IF NOT EXISTS seq_connection_id START 1;
CREATE SEQUENCE IF NOT EXISTS seq_enrichment_id START 1;
CREATE SEQUENCE IF NOT EXISTS seq_yara_id START 1;
CREATE SEQUENCE IF NOT EXISTS seq_ocr_id START 1;
CREATE SEQUENCE IF NOT EXISTS seq_stinger_id START 1;
CREATE SEQUENCE IF NOT EXISTS seq_log_id START 1;
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
        "artifact_id": "refined_google_searches",
        "category": "REFINED RESULTS",
        "display_name": "Google Searches",
        "table_name": "view_refined_google_searches",
        "source_tool": "RefinedResults",
        "ddl": """CREATE OR REPLACE VIEW view_refined_google_searches AS
            SELECT row_number() OVER () AS _row_id,
                   regexp_extract(url, '[?&]q=([^&]+)', 1) AS search_query,
                   url, title, visit_time, browser, source_file
            FROM (
                SELECT url, title, visit_time, 'Edge' AS browser, source_file FROM parsed_edge_history
                WHERE url ILIKE '%google.%/search%' OR url ILIKE '%google.%?q=%'
                UNION ALL
                SELECT url, title, visit_time, 'Chrome' AS browser, source_file FROM parsed_chrome_history
                WHERE url ILIKE '%google.%/search%' OR url ILIKE '%google.%?q=%'
                UNION ALL
                SELECT url, title, visit_time, 'Brave' AS browser, source_file FROM parsed_brave_history
                WHERE url ILIKE '%google.%/search%' OR url ILIKE '%google.%?q=%'
                UNION ALL
                SELECT url, title, visit_time, 'Firefox' AS browser, source_file FROM parsed_firefox_history
                WHERE url ILIKE '%google.%/search%' OR url ILIKE '%google.%?q=%'
            ) g_sub
            WHERE search_query IS NOT NULL AND length(search_query) > 0;"""
    },
    {
        "artifact_id": "refined_search_queries",
        "category": "REFINED RESULTS",
        "display_name": "Parsed Search Queries",
        "table_name": "view_refined_search_queries",
        "source_tool": "RefinedResults",
        "ddl": """CREATE OR REPLACE VIEW view_refined_search_queries AS
            SELECT row_number() OVER () AS _row_id,
                   CASE
                       WHEN url ILIKE '%google.%' THEN 'Google'
                       WHEN url ILIKE '%bing.com%' THEN 'Bing'
                       WHEN url ILIKE '%duckduckgo.com%' THEN 'DuckDuckGo'
                       WHEN url ILIKE '%yahoo.com%' THEN 'Yahoo'
                       ELSE 'Other Search'
                   END AS search_engine,
                   COALESCE(
                       NULLIF(regexp_extract(url, '[?&]q=([^&]+)', 1), ''),
                       NULLIF(regexp_extract(url, '[?&]p=([^&]+)', 1), ''),
                       regexp_extract(url, '[?&]query=([^&]+)', 1)
                   ) AS search_query,
                   url, title, visit_time, browser, source_file
            FROM (
                SELECT url, title, visit_time, 'Edge' AS browser, source_file FROM parsed_edge_history
                WHERE url ILIKE '%search%' OR url ILIKE '%?q=%' OR url ILIKE '%&q=%'
                UNION ALL
                SELECT url, title, visit_time, 'Chrome' AS browser, source_file FROM parsed_chrome_history
                WHERE url ILIKE '%search%' OR url ILIKE '%?q=%' OR url ILIKE '%&q=%'
                UNION ALL
                SELECT url, title, visit_time, 'Brave' AS browser, source_file FROM parsed_brave_history
                WHERE url ILIKE '%search%' OR url ILIKE '%?q=%' OR url ILIKE '%&q=%'
                UNION ALL
                SELECT url, title, visit_time, 'Firefox' AS browser, source_file FROM parsed_firefox_history
                WHERE url ILIKE '%search%' OR url ILIKE '%?q=%' OR url ILIKE '%&q=%'
            ) s_sub
            WHERE search_query IS NOT NULL AND length(search_query) > 0;"""
    },
    {
        "artifact_id": "refined_users",
        "category": "REFINED RESULTS",
        "display_name": "Identifiers & User Accounts",
        "table_name": "view_refined_users",
        "source_tool": "RefinedResults",
        "ddl": """CREATE OR REPLACE VIEW view_refined_users AS
            SELECT row_number() OVER () AS _row_id,
                   user_identifier,
                   source_artifact,
                   COUNT(*) AS occurrences,
                   MIN(timestamp_utc) AS first_observed,
                   MAX(timestamp_utc) AS last_observed
            FROM (
                SELECT CAST(UserName AS VARCHAR) AS user_identifier, 'Security & System Event Logs' AS source_artifact, TRY_CAST(TimeCreated AS TIMESTAMP) AS timestamp_utc
                FROM raw_evtx WHERE UserName IS NOT NULL AND TRIM(CAST(UserName AS VARCHAR)) NOT IN ('', '-', 'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'N/A')
                UNION ALL
                SELECT CAST(username AS VARCHAR) AS user_identifier, 'PowerShell Console Host History' AS source_artifact, CAST(NULL AS TIMESTAMP) AS timestamp_utc
                FROM parsed_powershell_history WHERE username IS NOT NULL AND TRIM(CAST(username AS VARCHAR)) != ''
                UNION ALL
                SELECT CAST(UserId AS VARCHAR) AS user_identifier, 'SRUM Application Resource Usage' AS source_artifact, TRY_CAST(Timestamp AS TIMESTAMP) AS timestamp_utc
                FROM raw_srum_app WHERE UserId IS NOT NULL AND TRIM(CAST(UserId AS VARCHAR)) NOT IN ('', '0')
                UNION ALL
                SELECT CAST(username_value AS VARCHAR) AS user_identifier, 'Edge Logins' AS source_artifact, TRY_CAST(date_created AS TIMESTAMP) AS timestamp_utc
                FROM parsed_edge_logins WHERE username_value IS NOT NULL AND TRIM(CAST(username_value AS VARCHAR)) != ''
                UNION ALL
                SELECT CAST(username_value AS VARCHAR) AS user_identifier, 'Chrome Logins' AS source_artifact, TRY_CAST(date_created AS TIMESTAMP) AS timestamp_utc
                FROM parsed_chrome_logins WHERE username_value IS NOT NULL AND TRIM(CAST(username_value AS VARCHAR)) != ''
                UNION ALL
                SELECT CAST(sender AS VARCHAR) AS user_identifier, 'Microsoft Teams Messages' AS source_artifact, TRY_CAST(timestamp_utc AS TIMESTAMP) AS timestamp_utc
                FROM parsed_teams_messages WHERE sender IS NOT NULL AND TRIM(CAST(sender AS VARCHAR)) != ''
            ) u_sub
            WHERE user_identifier IS NOT NULL AND length(trim(user_identifier)) > 0
            GROUP BY user_identifier, source_artifact
            ORDER BY occurrences DESC;"""
    },
    {
        "artifact_id": "refined_cloud_urls",
        "category": "REFINED RESULTS",
        "display_name": "Cloud Services URLs",
        "table_name": "view_refined_cloud_urls",
        "source_tool": "RefinedResults",
        "ddl": """CREATE OR REPLACE VIEW view_refined_cloud_urls AS
            SELECT row_number() OVER () AS _row_id, url, title, visit_time, browser, source_file
            FROM (
                SELECT url, title, visit_time, 'Edge' AS browser, source_file FROM parsed_edge_history
                WHERE url ILIKE '%drive.google.com%' OR url ILIKE '%onedrive.live.com%' OR url ILIKE '%dropbox.com%' OR url ILIKE '%box.com%' OR url ILIKE '%sharepoint.com%'
                UNION ALL
                SELECT url, title, visit_time, 'Chrome' AS browser, source_file FROM parsed_chrome_history
                WHERE url ILIKE '%drive.google.com%' OR url ILIKE '%onedrive.live.com%' OR url ILIKE '%dropbox.com%' OR url ILIKE '%box.com%' OR url ILIKE '%sharepoint.com%'
                UNION ALL
                SELECT url, title, visit_time, 'Brave' AS browser, source_file FROM parsed_brave_history
                WHERE url ILIKE '%drive.google.com%' OR url ILIKE '%onedrive.live.com%' OR url ILIKE '%dropbox.com%' OR url ILIKE '%box.com%' OR url ILIKE '%sharepoint.com%'
                UNION ALL
                SELECT url, title, visit_time, 'Firefox' AS browser, source_file FROM parsed_firefox_history
                WHERE url ILIKE '%drive.google.com%' OR url ILIKE '%onedrive.live.com%' OR url ILIKE '%dropbox.com%' OR url ILIKE '%box.com%' OR url ILIKE '%sharepoint.com%'
            ) c_sub;"""
    },
    {
        "artifact_id": "refined_social_urls",
        "category": "REFINED RESULTS",
        "display_name": "Social Media URLs",
        "table_name": "view_refined_social_urls",
        "source_tool": "RefinedResults",
        "ddl": """CREATE OR REPLACE VIEW view_refined_social_urls AS
            SELECT row_number() OVER () AS _row_id, url, title, visit_time, browser, source_file
            FROM (
                SELECT url, title, visit_time, 'Edge' AS browser, source_file FROM parsed_edge_history
                WHERE url ILIKE '%facebook.com%' OR url ILIKE '%twitter.com%' OR url ILIKE '%x.com%' OR url ILIKE '%linkedin.com%' OR url ILIKE '%instagram.com%' OR url ILIKE '%reddit.com%' OR url ILIKE '%tiktok.com%'
                UNION ALL
                SELECT url, title, visit_time, 'Chrome' AS browser, source_file FROM parsed_chrome_history
                WHERE url ILIKE '%facebook.com%' OR url ILIKE '%twitter.com%' OR url ILIKE '%x.com%' OR url ILIKE '%linkedin.com%' OR url ILIKE '%instagram.com%' OR url ILIKE '%reddit.com%' OR url ILIKE '%tiktok.com%'
                UNION ALL
                SELECT url, title, visit_time, 'Brave' AS browser, source_file FROM parsed_brave_history
                WHERE url ILIKE '%facebook.com%' OR url ILIKE '%twitter.com%' OR url ILIKE '%x.com%' OR url ILIKE '%linkedin.com%' OR url ILIKE '%instagram.com%' OR url ILIKE '%reddit.com%' OR url ILIKE '%tiktok.com%'
                UNION ALL
                SELECT url, title, visit_time, 'Firefox' AS browser, source_file FROM parsed_firefox_history
                WHERE url ILIKE '%facebook.com%' OR url ILIKE '%twitter.com%' OR url ILIKE '%x.com%' OR url ILIKE '%linkedin.com%' OR url ILIKE '%instagram.com%' OR url ILIKE '%reddit.com%' OR url ILIKE '%tiktok.com%'
            ) s_sub;"""
    },
    {
        "artifact_id": "refined_domains",
        "category": "REFINED RESULTS",
        "display_name": "Top Domains & URLs",
        "table_name": "view_refined_domains",
        "source_tool": "RefinedResults",
        "ddl": """CREATE OR REPLACE VIEW view_refined_domains AS
            SELECT row_number() OVER () AS _row_id,
                   domain,
                   COUNT(*) AS event_count,
                   COUNT(DISTINCT source_artifact) AS distinct_artifacts_count,
                   MIN(timestamp_utc) AS first_seen,
                   MAX(timestamp_utc) AS last_seen,
                   string_agg(DISTINCT source_artifact, ', ') AS observed_in_artifacts
            FROM (
                SELECT regexp_extract(url, 'https?://([^/:]+)', 1) AS domain, 'Edge Web History' AS source_artifact, TRY_CAST(visit_time AS TIMESTAMP) AS timestamp_utc
                FROM parsed_edge_history WHERE url IS NOT NULL AND length(url) > 0
                UNION ALL
                SELECT regexp_extract(url, 'https?://([^/:]+)', 1) AS domain, 'Chrome Web History' AS source_artifact, TRY_CAST(visit_time AS TIMESTAMP) AS timestamp_utc
                FROM parsed_chrome_history WHERE url IS NOT NULL AND length(url) > 0
                UNION ALL
                SELECT regexp_extract(url, 'https?://([^/:]+)', 1) AS domain, 'Brave Web History' AS source_artifact, TRY_CAST(visit_time AS TIMESTAMP) AS timestamp_utc
                FROM parsed_brave_history WHERE url IS NOT NULL AND length(url) > 0
                UNION ALL
                SELECT regexp_extract(url, 'https?://([^/:]+)', 1) AS domain, 'Firefox Web History' AS source_artifact, TRY_CAST(visit_time AS TIMESTAMP) AS timestamp_utc
                FROM parsed_firefox_history WHERE url IS NOT NULL AND length(url) > 0
                UNION ALL
                SELECT regexp_extract(COALESCE(tab_url, site_url), 'https?://([^/:]+)', 1) AS domain, 'Edge Downloads' AS source_artifact, TRY_CAST(start_time AS TIMESTAMP) AS timestamp_utc
                FROM parsed_edge_downloads WHERE COALESCE(tab_url, site_url) IS NOT NULL AND length(COALESCE(tab_url, site_url)) > 0
                UNION ALL
                SELECT regexp_extract(COALESCE(tab_url, site_url), 'https?://([^/:]+)', 1) AS domain, 'Chrome Downloads' AS source_artifact, TRY_CAST(start_time AS TIMESTAMP) AS timestamp_utc
                FROM parsed_chrome_downloads WHERE COALESCE(tab_url, site_url) IS NOT NULL AND length(COALESCE(tab_url, site_url)) > 0
            ) d_sub
            WHERE domain IS NOT NULL AND length(trim(domain)) > 0
            GROUP BY domain
            ORDER BY event_count DESC;"""
    },
    {
        "artifact_id": "refined_keyword_hits",
        "category": "REFINED RESULTS",
        "display_name": "Keyword Hits",
        "table_name": "view_keyword_hits",
        "source_tool": "KeywordScanner",
        "ddl": """CREATE OR REPLACE VIEW view_keyword_hits AS
            SELECT row_number() OVER () AS _row_id,
                   keyword_id, keyword, is_regex, source_file, hit_count, created_at
            FROM case_keywords WHERE hit_count > 0;"""
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
            _row_id BIGINT, window_id BIGINT, tab_id BIGINT, url VARCHAR, title VARCHAR, active BOOLEAN, last_active_time TIMESTAMP, source_file VARCHAR
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
        "display_name": "Chrome Web History",
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
            _row_id BIGINT, window_id BIGINT, tab_id BIGINT, url VARCHAR, title VARCHAR, active BOOLEAN, last_active_time TIMESTAMP, source_file VARCHAR
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
        "display_name": "Edge Web History",
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
        "display_name": "Brave Web History",
        "table_name": "parsed_brave_history",
        "source_tool": "ChromiumParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_brave_history (
            _row_id BIGINT, browser VARCHAR, profile VARCHAR, url VARCHAR, title VARCHAR, visit_count INTEGER, typed_count INTEGER, visit_time TIMESTAMP, from_visit BIGINT, transition VARCHAR, source_file VARCHAR
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
            _row_id BIGINT, title VARCHAR, url VARCHAR, date_added TIMESTAMP, last_modified TIMESTAMP, folder_name VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "firefox_cookies",
        "category": "WEB RELATED",
        "display_name": "Firefox Cookies",
        "table_name": "parsed_firefox_cookies",
        "source_tool": "FirefoxParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_firefox_cookies (
            _row_id BIGINT, host VARCHAR, name VARCHAR, value VARCHAR, path VARCHAR, expiry TIMESTAMP, last_accessed TIMESTAMP, creation_time TIMESTAMP, is_secure BOOLEAN, is_http_only BOOLEAN, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "firefox_downloads",
        "category": "WEB RELATED",
        "display_name": "Firefox Downloads",
        "table_name": "parsed_firefox_downloads",
        "source_tool": "FirefoxParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_firefox_downloads (
            _row_id BIGINT, target_path VARCHAR, url VARCHAR, total_bytes BIGINT, start_time TIMESTAMP, end_time TIMESTAMP, mime_type VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "firefox_formhistory",
        "category": "WEB RELATED",
        "display_name": "Firefox FormHistory",
        "table_name": "parsed_firefox_formhistory",
        "source_tool": "FirefoxParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_firefox_formhistory (
            _row_id BIGINT, field_name VARCHAR, value VARCHAR, times_used INTEGER, first_used TIMESTAMP, last_used TIMESTAMP, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "firefox_history",
        "category": "WEB RELATED",
        "display_name": "Firefox Web History",
        "table_name": "parsed_firefox_history",
        "source_tool": "FirefoxParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_firefox_history (
            _row_id BIGINT, browser VARCHAR, profile VARCHAR, url VARCHAR, title VARCHAR, visit_count INTEGER, typed_count INTEGER, visit_time TIMESTAMP, from_visit BIGINT, transition VARCHAR, source_file VARCHAR
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
            _row_id BIGINT, app_id VARCHAR, timestamp_utc TIMESTAMP, title VARCHAR, body VARCHAR, header VARCHAR, action_url VARCHAR, source_file VARCHAR
        );"""
    },

    # -------------------------------------------------------------------------
    # 4. EMAIL (Split per client/type)
    # -------------------------------------------------------------------------
    {
        "artifact_id": "outlook_emails",
        "category": "EMAIL",
        "display_name": "Outlook PST/OST Emails",
        "table_name": "parsed_outlook_emails",
        "source_tool": "EmailParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_outlook_emails (
            _row_id BIGINT, email_format VARCHAR, sender VARCHAR, recipients VARCHAR, cc VARCHAR, bcc VARCHAR, subject VARCHAR, date_utc TIMESTAMP, message_id VARCHAR, body_snippet VARCHAR, attachments_count INTEGER, attachment_names VARCHAR, client_submit_time TIMESTAMP, is_suspicious BOOLEAN, suspicious_indicators VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "outlook_contacts",
        "category": "EMAIL",
        "display_name": "Outlook Contacts & Calendar",
        "table_name": "parsed_outlook_contacts",
        "source_tool": "EmailParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_outlook_contacts (
            _row_id BIGINT, item_type VARCHAR, display_name VARCHAR, email_address VARCHAR, start_time TIMESTAMP, end_time TIMESTAMP, location VARCHAR, subject VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "email_attachments",
        "category": "EMAIL",
        "display_name": "Email Attachments",
        "table_name": "parsed_email_attachments",
        "source_tool": "EmailParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_email_attachments (
            _row_id BIGINT, email_id VARCHAR, file_name VARCHAR, file_size BIGINT, mime_type VARCHAR, sha256 VARCHAR, is_malicious BOOLEAN, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "mbox_emails",
        "category": "EMAIL",
        "display_name": "Thunderbird / MBOX Emails",
        "table_name": "parsed_mbox_emails",
        "source_tool": "EmailParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_mbox_emails (
            _row_id BIGINT, email_format VARCHAR, sender VARCHAR, recipients VARCHAR, cc VARCHAR, bcc VARCHAR, subject VARCHAR, date_utc TIMESTAMP, message_id VARCHAR, body_snippet VARCHAR, attachments_count INTEGER, attachment_names VARCHAR, client_submit_time TIMESTAMP, is_suspicious BOOLEAN, suspicious_indicators VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "winmail_messages",
        "category": "EMAIL",
        "display_name": "Windows Mail Messages",
        "table_name": "parsed_winmail_messages",
        "source_tool": "EmailParser",
        "ddl": """CREATE TABLE IF NOT EXISTS parsed_winmail_messages (
            _row_id BIGINT, email_format VARCHAR, sender VARCHAR, recipients VARCHAR, cc VARCHAR, bcc VARCHAR, subject VARCHAR, date_utc TIMESTAMP, message_id VARCHAR, body_snippet VARCHAR, attachments_count INTEGER, attachment_names VARCHAR, client_submit_time TIMESTAMP, is_suspicious BOOLEAN, suspicious_indicators VARCHAR, source_file VARCHAR
        );"""
    },
    {
        "artifact_id": "emails",
        "category": "EMAIL",
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
            SELECT row_number() OVER () AS _row_id, file_name, file_path, file_size_bytes, created_time, modified_time, author, title, sha256, source_evidence
            FROM (
                SELECT file_name, file_path, file_size_bytes, created_time, modified_time, author, title, sha256, source_evidence,
                       row_number() OVER (PARTITION BY LOWER(file_name), file_size_bytes ORDER BY (CASE WHEN source_evidence = 'parsed_documents_metadata' THEN 1 ELSE 2 END) ASC, modified_time DESC NULLS LAST) AS _final_rn
                FROM (
                    SELECT file_name, file_path, file_size_bytes, created_time, modified_time, author, title, sha256, 'parsed_documents_metadata' AS source_evidence
                    FROM parsed_documents_metadata 
                    WHERE (LOWER(COALESCE(file_type, '')) IN ('txt', 'log', 'ini', 'cfg', 'conf', 'json', 'xml') OR file_name ILIKE '%.txt' OR file_name ILIKE '%.log')
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
            ) doc_sub WHERE _dup_rn = 1;"""
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
        "artifact_id": "view_autoruns",
        "category": "OPERATING SYSTEM",
        "display_name": "Autorun & Startup Items",
        "table_name": "view_autoruns",
        "source_tool": "RECmd.exe",
        "ddl": """CREATE OR REPLACE VIEW view_autoruns AS
            SELECT * FROM raw_recmd WHERE (Category LIKE '%Run%' OR KeyPath LIKE '%CurrentVersion\\Run%' OR KeyPath LIKE '%Services%');"""
    },
    {
        "artifact_id": "view_bam_dam",
        "category": "OPERATING SYSTEM",
        "display_name": "Background Activity Moderator (BAM/DAM)",
        "table_name": "view_bam_dam",
        "source_tool": "RECmd.exe",
        "ddl": """CREATE OR REPLACE VIEW view_bam_dam AS
            SELECT * FROM raw_recmd WHERE (KeyPath LIKE '%bam%' OR KeyPath LIKE '%dam%' OR Description LIKE '%bam%' OR Description LIKE '%dam%');"""
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
            _row_id BIGINT, EntryNumber BIGINT, SequenceNumber INTEGER, InUse BOOLEAN, ParentEntryNumber BIGINT, ParentSequenceNumber INTEGER, ParentPath VARCHAR, FileName VARCHAR, Extension VARCHAR, FileSize BIGINT, Created0x10 TIMESTAMP, Created0x30 TIMESTAMP, LastModified0x10 TIMESTAMP, LastModified0x30 TIMESTAMP, LastAccess0x10 TIMESTAMP, LastRecordChange0x10 TIMESTAMP, TimestampsLogicalInconsistency BOOLEAN
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
        "source_tool": "RECmd.exe",
        "ddl": """CREATE OR REPLACE VIEW view_userassist AS
            SELECT * FROM raw_recmd WHERE (Category LIKE '%UserAssist%' OR Description LIKE '%UserAssist%' OR KeyPath LIKE '%UserAssist%');"""
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
            _row_id BIGINT, file_path VARCHAR NOT NULL, file_name VARCHAR NOT NULL, extension VARCHAR, size_bytes BIGINT, sha256 VARCHAR, rule_name VARCHAR NOT NULL, rule_namespace VARCHAR, pattern_identifier VARCHAR, match_offset BIGINT, match_length BIGINT, match_data_hex VARCHAR, scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );"""
    },
    {
        "artifact_id": "malware_stinger_hits",
        "category": "MALWARE & YARA",
        "display_name": "Trellix Stinger & PE Threat Hits",
        "table_name": "artifact_stinger_hits",
        "source_tool": "TrellixStingerEngine",
        "ddl": """CREATE TABLE IF NOT EXISTS artifact_stinger_hits (
            _row_id BIGINT, file_path VARCHAR NOT NULL, file_name VARCHAR NOT NULL, sha256 VARCHAR, malware_name VARCHAR, detection_type VARCHAR, action_taken VARCHAR, engine_version VARCHAR, details VARCHAR, scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );"""
    },
    {
        "artifact_id": "malware_all_detections",
        "category": "MALWARE & YARA",
        "display_name": "All Malware & Threat Detections",
        "table_name": "view_all_malware_detections",
        "source_tool": "MalwareScanner",
        "ddl": """CREATE OR REPLACE VIEW view_all_malware_detections AS
            SELECT row_number() OVER () AS _row_id, file_name, file_path, sha256,
                   malware_name AS detection_name, detection_type, 'Stinger / PE Threat Scanner' AS engine,
                   details, scanned_at
            FROM artifact_stinger_hits
            UNION ALL
            SELECT row_number() OVER () AS _row_id, file_name, file_path, sha256,
                   rule_name AS detection_name, 'YARA-X Rule Match' AS detection_type, 'YARA-X' AS engine,
                   'Namespace: ' || COALESCE(rule_namespace, 'default') || ' | Pattern: ' || COALESCE(pattern_identifier, 'string') || ' @ ' || COALESCE(CAST(match_offset AS VARCHAR), '0') AS details,
                   scanned_at
            FROM artifact_yara_hits;"""
    },
]


def register_evtx_granular_views(conn: duckdb.DuckDBPyConnection, case_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Dynamically creates dedicated DuckDB views for EVERY individual .evtx file present in raw_evtx
    and registers each view in artifact_registry under category = 'EVENT LOGS'.
    Also ensures 'All Event Logs (Combined)' (raw_evtx) is registered under 'EVENT LOGS'.
    """
    created_views: List[Dict[str, Any]] = []
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
            return created_views

        file_counts = cursor.execute(evtx_query).fetchall()
        if not file_counts:
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

            # Escape single quotes in filenames for SQL safety
            escaped_file = evtx_file_str.replace("'", "''")
            escaped_raw_base = raw_base.replace("'", "''")
            escaped_clean_base = clean_base.replace("'", "''")

            # Create filtered view in DuckDB
            if has_source_file and has_channel:
                view_sql = f"""
                CREATE OR REPLACE VIEW "{view_name}" AS
                SELECT * FROM raw_evtx
                WHERE regexp_extract(COALESCE(SourceFile, ''), '([^\\\\/]+\\.evtx)$', 1) = '{escaped_file}'
                   OR SourceFile ILIKE '%{escaped_file}'
                   OR Channel = '{escaped_raw_base}'
                   OR Channel = '{escaped_clean_base}';
                """
            elif has_source_file:
                view_sql = f"""
                CREATE OR REPLACE VIEW "{view_name}" AS
                SELECT * FROM raw_evtx
                WHERE regexp_extract(COALESCE(SourceFile, ''), '([^\\\\/]+\\.evtx)$', 1) = '{escaped_file}'
                   OR SourceFile ILIKE '%{escaped_file}';
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

    except Exception as ex:
        print(f"[Schema] Error registering dynamic evtx views: {ex}")

    return created_views


register_dynamic_evtx_views = register_evtx_granular_views


def sync_granular_artifacts(conn: duckdb.DuckDBPyConnection, case_id: Optional[str] = None) -> None:
    """
    Synchronizes granular browser, chat, email, cloud, media, document, and event log tables
    from any populated combined or raw tables, ensuring zero stubs and accurate row counts.
    """
    try:
        cursor = conn.cursor()
        tables_in_db = set(
            r[0]
            for r in cursor.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
            ).fetchall()
        )

        def safe_sync_table(src: str, dst: str, filter_sql: str) -> None:
            if src not in tables_in_db or dst not in tables_in_db:
                return
            src_cols = [r[1] for r in cursor.execute(f'PRAGMA table_info("{src}");').fetchall()]
            dst_cols = [r[1] for r in cursor.execute(f'PRAGMA table_info("{dst}");').fetchall()]
            common = [c for c in src_cols if c in dst_cols]
            if not common:
                return
            cols_str = ", ".join([f'"{c}"' for c in common])
            cursor.execute(f"""
                INSERT INTO "{dst}" ({cols_str})
                SELECT {cols_str} FROM "{src}" WHERE {filter_sql}
                EXCEPT
                SELECT {cols_str} FROM "{dst}";
            """)

        # 1. Web Browsers History Sync
        safe_sync_table("parsed_browser_history", "parsed_chrome_history", "LOWER(COALESCE(browser, '')) IN ('chrome', 'chromium')")
        safe_sync_table("parsed_browser_history", "parsed_edge_history", "LOWER(COALESCE(browser, '')) LIKE '%edge%'")
        safe_sync_table("parsed_browser_history", "parsed_brave_history", "LOWER(COALESCE(browser, '')) LIKE '%brave%'")
        safe_sync_table("parsed_browser_history", "parsed_firefox_history", "LOWER(COALESCE(browser, '')) LIKE '%firefox%'")

        # 2. Web Browsers Downloads Sync
        safe_sync_table("parsed_browser_downloads", "parsed_chrome_downloads", "LOWER(COALESCE(browser, '')) IN ('chrome', 'chromium')")
        safe_sync_table("parsed_browser_downloads", "parsed_edge_downloads", "LOWER(COALESCE(browser, '')) LIKE '%edge%'")
        safe_sync_table("parsed_browser_downloads", "parsed_brave_downloads", "LOWER(COALESCE(browser, '')) LIKE '%brave%'")
        safe_sync_table("parsed_browser_downloads", "parsed_firefox_downloads", "LOWER(COALESCE(browser, '')) LIKE '%firefox%'")

        # 3. Web Browsers Logins Sync
        safe_sync_table("parsed_browser_logins", "parsed_chrome_logins", "LOWER(COALESCE(browser, '')) IN ('chrome', 'chromium')")
        safe_sync_table("parsed_browser_logins", "parsed_edge_logins", "LOWER(COALESCE(browser, '')) LIKE '%edge%'")
        safe_sync_table("parsed_browser_logins", "parsed_brave_logins", "LOWER(COALESCE(browser, '')) LIKE '%brave%'")

        # Explicitly purge legacy combined browser entries from artifact_registry
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

        # 7. Media Pictures & Videos Sync
        if "parsed_media_exif" in tables_in_db:
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
                cursor.execute(f"""
                    INSERT INTO parsed_media_pictures (
                        _row_id, file_path, file_name, file_type, file_size_bytes, sha256, camera_make, camera_model,
                        datetime_original, software, image_width, image_height, latitude, longitude, gps_position, gps_coordinates,
                        raw_metadata, source_file
                    )
                    SELECT
                        _row_id, file_path, file_name, file_type, file_size_bytes, sha256, camera_make, camera_model,
                        datetime_original, software, {w_expr}, {h_expr}, {lat_expr}, {lon_expr}, {pos_expr}, {coord_expr},
                        {raw_expr}, {src_expr}
                    FROM parsed_media_exif
                    WHERE LOWER(COALESCE(file_type, '')) IN ('jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'tiff', 'heic', 'image')
                    EXCEPT SELECT
                        _row_id, file_path, file_name, file_type, file_size_bytes, sha256, camera_make, camera_model,
                        datetime_original, software, image_width, image_height, latitude, longitude, gps_position, gps_coordinates,
                        raw_metadata, source_file
                    FROM parsed_media_pictures;
                """)

            if "parsed_media_videos" in tables_in_db:
                has_dur = "duration_seconds" in exif_cols
                dur_expr = "duration_seconds" if has_dur else "CAST(NULL AS DOUBLE)"
                cursor.execute(f"""
                    INSERT INTO parsed_media_videos (
                        _row_id, file_path, file_name, file_type, file_size_bytes, sha256, datetime_original,
                        duration_seconds, width, height, raw_metadata, source_file
                    )
                    SELECT
                        _row_id, file_path, file_name, file_type, file_size_bytes, sha256, datetime_original,
                        {dur_expr}, {w_expr}, {h_expr}, {raw_expr}, {src_expr}
                    FROM parsed_media_exif
                    WHERE LOWER(COALESCE(file_type, '')) IN ('mp4', 'mov', 'avi', 'mkv', 'wmv', 'flv', 'video')
                    EXCEPT SELECT
                        _row_id, file_path, file_name, file_type, file_size_bytes, sha256, datetime_original,
                        duration_seconds, width, height, raw_metadata, source_file
                    FROM parsed_media_videos;
                """)

        # 8. Dynamic EVTX Views
        register_evtx_granular_views(conn, case_id=case_id)

    except Exception as sync_ex:
        print(f"[Schema] Warning during granular artifacts synchronization: {sync_ex}")


def sync_artifact_registry_counts(conn: duckdb.DuckDBPyConnection, case_id: Optional[str] = None) -> int:
    """
    Synchronizes virtual views, granular tables, and live DuckDB row counts into artifact_registry.
    Ensures artifact_registry accurately reflects real rows in case.duckdb across all 10 canonical categories.
    Returns the total evidence count across all populated artifacts.
    """
    cursor = conn.cursor()
    tables_in_db = set(
        r[0]
        for r in cursor.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
        ).fetchall()
    )

    # 1. Ensure all virtual views are created/refreshed from populated tables
    # 1a. Recmd views (USB, AutoRuns, UserAssist, BAM/DAM)
    if "raw_recmd" in tables_in_db:
        recmd_views = [
            ("view_usb_devices", """CREATE OR REPLACE VIEW view_usb_devices AS
                SELECT * FROM raw_recmd WHERE (KeyPath ILIKE '%USBSTOR%' OR KeyPath ILIKE '%MountedDevices%' OR KeyPath ILIKE '%EMDMgmt%' OR Description ILIKE '%USB%');"""),
            ("view_autoruns", """CREATE OR REPLACE VIEW view_autoruns AS
                SELECT * FROM raw_recmd WHERE (Category ILIKE '%Run%' OR KeyPath ILIKE '%CurrentVersion\\Run%' OR KeyPath ILIKE '%Services%');"""),
            ("view_userassist", """CREATE OR REPLACE VIEW view_userassist AS
                SELECT * FROM raw_recmd WHERE (Category ILIKE '%UserAssist%' OR Description ILIKE '%UserAssist%' OR KeyPath ILIKE '%UserAssist%');"""),
            ("view_bam_dam", """CREATE OR REPLACE VIEW view_bam_dam AS
                SELECT * FROM raw_recmd WHERE (KeyPath ILIKE '%bam%' OR KeyPath ILIKE '%dam%' OR Description ILIKE '%bam%' OR Description ILIKE '%dam%');"""),
        ]
        for vname, ddl in recmd_views:
            try:
                cursor.execute(ddl)
                tables_in_db.add(vname)
            except Exception as ex:
                print(f"[Schema] Warning creating recmd view {vname}: {ex}")

    # 1b. Document views from raw_mft or parsed_documents_metadata
    if "raw_mft" in tables_in_db or "parsed_documents_metadata" in tables_in_db:
        doc_views = [
            ("view_docs_pdf", """CREATE OR REPLACE VIEW view_docs_pdf AS
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
                ) ranked_p WHERE _final_rn = 1;"""),
            ("view_docs_word", """CREATE OR REPLACE VIEW view_docs_word AS
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
                ) ranked_w WHERE _final_rn = 1;"""),
            ("view_docs_excel", """CREATE OR REPLACE VIEW view_docs_excel AS
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
                ) ranked_e WHERE _final_rn = 1;"""),
            ("view_docs_ppt", """CREATE OR REPLACE VIEW view_docs_ppt AS
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
                ) ranked_ppt WHERE _final_rn = 1;"""),
            ("view_docs_txt", """CREATE OR REPLACE VIEW view_docs_txt AS
                SELECT row_number() OVER () AS _row_id, file_name, file_path, file_size_bytes, created_time, modified_time, author, title, sha256, source_evidence
                FROM (
                    SELECT file_name, file_path, file_size_bytes, created_time, modified_time, author, title, sha256, source_evidence,
                           row_number() OVER (PARTITION BY LOWER(file_name), file_size_bytes ORDER BY (CASE WHEN source_evidence = 'parsed_documents_metadata' THEN 1 ELSE 2 END) ASC, modified_time DESC NULLS LAST) AS _final_rn
                    FROM (
                        SELECT file_name, file_path, file_size_bytes, created_time, modified_time, author, title, sha256, 'parsed_documents_metadata' AS source_evidence
                        FROM parsed_documents_metadata 
                        WHERE (LOWER(COALESCE(file_type, '')) IN ('txt', 'log', 'ini', 'cfg', 'conf', 'json', 'xml') OR file_name ILIKE '%.txt' OR file_name ILIKE '%.log')
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
                    ) t_sub
                ) ranked_t WHERE _final_rn = 1;"""),
            ("view_documents", """CREATE OR REPLACE VIEW view_documents AS
                SELECT row_number() OVER () AS _row_id, file_name, file_path, extension, file_size_bytes, created_time, modified_time, source_evidence
                FROM (
                    SELECT FileName AS file_name, COALESCE(ParentPath, '') || '\\\\' || COALESCE(FileName, '') AS file_path, LOWER(Extension) AS extension, FileSize AS file_size_bytes, Created0x10 AS created_time, LastModified0x10 AS modified_time, 'raw_mft' AS source_evidence,
                           row_number() OVER (PARTITION BY LOWER(COALESCE(ParentPath, '')), LOWER(COALESCE(FileName, '')), FileSize ORDER BY LastModified0x10 DESC NULLS LAST) AS _dup_rn
                    FROM raw_mft 
                    WHERE LOWER(COALESCE(Extension, '')) IN ('.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.csv')
                      AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\winsxs%'
                      AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\system32%'
                      AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\syswow64%'
                      AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\servicing%'
                      AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\windows\\\\installer%'
                      AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\program files%'
                      AND REPLACE(LOWER(COALESCE(ParentPath, '')), '/', '\\\\') NOT LIKE '%\\\\programdata\\\\microsoft%'
                      AND LOWER(COALESCE(FileName, '')) NOT IN ('msoirmprotector.doc', 'msoirmprotector.ppt', 'msoirmprotector.xls')
                ) doc_sub WHERE _dup_rn = 1;"""),
        ]
        for vname, ddl in doc_views:
            try:
                cursor.execute(ddl)
                tables_in_db.add(vname)
            except Exception as ex:
                print(f"[Schema] Warning creating doc view {vname}: {ex}")

    # 1c. Refined results views from MASTER_ARTIFACT_CATALOG
    for entry in MASTER_ARTIFACT_CATALOG:
        if entry["table_name"].startswith("view_refined_"):
            try:
                cursor.execute(entry["ddl"])
                tables_in_db.add(entry["table_name"])
            except Exception:
                pass

    # 2. Granular sub-tables sync & dynamic EVTX views
    try:
        sync_granular_artifacts(conn, case_id=case_id)
    except Exception as s_ex:
        print(f"[Schema] Warning in sync_granular_artifacts: {s_ex}")

    try:
        register_evtx_granular_views(conn, case_id=case_id)
    except Exception as e_ex:
        print(f"[Schema] Warning in register_evtx_granular_views: {e_ex}")

    # 3. Ensure all catalog entries are in artifact_registry
    for entry in MASTER_ARTIFACT_CATALOG:
        art_id = entry["artifact_id"]
        cat = entry["category"]
        disp = entry["display_name"]
        tbl = entry["table_name"]
        src = entry["source_tool"]
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
                [art_id, cat, disp, tbl, src],
            )
        except Exception:
            pass

    # 4. Standardize categories
    try:
        cursor.execute("""
            DELETE FROM artifact_registry 
            WHERE artifact_id IN ('media_exif', 'documents_metadata', 'media_ocr_results', 'ocr_extracted_text', 'ocr_results')
               OR table_name IN ('parsed_media_exif', 'parsed_documents_metadata')
               OR display_name LIKE '%(Combined)%' OR artifact_id IN ('cloud_files', 'chat_messages', 'emails', 'view_documents', 'docs_txt');

            UPDATE artifact_registry SET category = 'EVENT LOGS'
            WHERE category IN ('Event Logs', 'EVENT LOGS') OR table_name = 'raw_evtx' OR table_name LIKE 'view_evtx_%';

            UPDATE artifact_registry SET category = 'OPERATING SYSTEM'
            WHERE (category IN ('Program Execution', 'File System', 'Registry & OS', 'Network & SRUM', 'USB & External Devices', 'Operating System', 'USB & EXTERNAL DEVICES', 'OPERATING SYSTEM')
                   OR artifact_id IN ('view_usb_devices', 'view_autoruns', 'view_bam_dam', 'view_userassist'))
              AND table_name != 'raw_evtx' AND table_name NOT LIKE 'view_evtx_%';

            UPDATE artifact_registry SET category = 'WEB RELATED'
            WHERE category IN ('Web Browsers', 'Web Related', 'WEB RELATED');

            UPDATE artifact_registry SET category = 'CHAT'
            WHERE category IN ('Chat & Collaboration', 'Chat', 'CHAT');

            UPDATE artifact_registry SET category = 'EMAIL'
            WHERE category IN ('Email & Calendar', 'Email', 'EMAIL');

            UPDATE artifact_registry SET category = 'CLOUD'
            WHERE category IN ('Cloud Storage', 'Cloud', 'CLOUD');

            UPDATE artifact_registry SET category = 'MEDIA'
            WHERE category IN ('Media & Pictures', 'Media', 'MEDIA');

            UPDATE artifact_registry SET category = 'DOCUMENTS'
            WHERE category IN ('Documents', 'DOCUMENTS');

            UPDATE artifact_registry SET category = 'MALWARE & YARA'
            WHERE category IN ('Malware & Threat Hunting', 'Malware & YARA', 'MALWARE & YARA');

            UPDATE artifact_registry SET category = 'REFINED RESULTS'
            WHERE category IN ('Refined Results', 'REFINED RESULTS');
        """)
    except Exception as std_ex:
        print(f"[Schema] Warning standardizing categories: {std_ex}")

    # 5. Live row count sync for all registered tables
    tables_in_db = set(
        r[0]
        for r in cursor.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
        ).fetchall()
    )
    registered = cursor.execute("SELECT artifact_id, table_name FROM artifact_registry;").fetchall()
    for art_id, tname in registered:
        if tname in tables_in_db:
            try:
                cnt = cursor.execute(f'SELECT COUNT(*) FROM "{tname}";').fetchone()[0]
                cursor.execute(
                    "UPDATE artifact_registry SET row_count = ?, last_updated = CURRENT_TIMESTAMP WHERE artifact_id = ?;",
                    [cnt, art_id],
                )
            except Exception:
                pass
        else:
            try:
                cursor.execute(
                    "UPDATE artifact_registry SET row_count = 0, last_updated = CURRENT_TIMESTAMP WHERE artifact_id = ?;",
                    [art_id],
                )
            except Exception:
                pass

    # 6. Auto-register any uncataloged populated raw_* or parsed_* tables
    registered_tables = set(r[1] for r in registered)
    for tname in tables_in_db:
        if tname in ('parsed_browser_history', 'parsed_browser_downloads', 'parsed_browser_logins', 'parsed_media_exif', 'parsed_documents_metadata'):
            continue
        if tname not in registered_tables and (tname.startswith("raw_") or tname.startswith("parsed_")):
            try:
                cnt = cursor.execute(f'SELECT COUNT(*) FROM "{tname}";').fetchone()[0]
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
                    disp = tname.replace("raw_", "").replace("parsed_", "").replace("_", " ").title()
                    cursor.execute(
                        """
                        INSERT INTO artifact_registry (artifact_id, category, display_name, table_name, source_tool, row_count, last_updated)
                        VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                        ON CONFLICT (artifact_id) DO UPDATE SET row_count = EXCLUDED.row_count;
                        """,
                        [tname, cat, disp, tname, src, cnt],
                    )
            except Exception:
                pass

    total = cursor.execute("SELECT COALESCE(SUM(row_count), 0) FROM artifact_registry WHERE row_count > 0;").fetchone()[0]
    return int(total)


def init_schema(conn: duckdb.DuckDBPyConnection, case_id: Optional[str] = None) -> None:
    """
    Execute DDL on DuckDB connection to ensure all core tables and sequences exist,
    pre-populates artifact_registry across all 10 canonical WFT categories,
    and creates their empty schema tables/views so queries never fail.
    """
    cursor = conn.cursor()
    # 1. Execute core schema DDL
    cursor.execute(CORE_SCHEMA_SQL)

    # 2. Standardize artifact categories for existing cases
    try:
        cursor.execute("""
            UPDATE artifact_registry SET category = 'EVENT LOGS'
            WHERE category IN ('Event Logs', 'EVENT LOGS') OR table_name = 'raw_evtx' OR table_name LIKE 'view_evtx_%';

            UPDATE artifact_registry SET category = 'OPERATING SYSTEM'
            WHERE category IN ('Program Execution', 'File System', 'Registry & OS', 'Network & SRUM', 'USB & External Devices', 'Operating System')
              AND table_name != 'raw_evtx' AND table_name NOT LIKE 'view_evtx_%';

            UPDATE artifact_registry SET category = 'WEB RELATED'
            WHERE category IN ('Web Browsers', 'Web Related');

            UPDATE artifact_registry SET category = 'CHAT'
            WHERE category IN ('Chat & Collaboration', 'Chat');

            UPDATE artifact_registry SET category = 'EMAIL'
            WHERE category IN ('Email & Calendar', 'Email');

            UPDATE artifact_registry SET category = 'CLOUD'
            WHERE category IN ('Cloud Storage', 'Cloud');

            UPDATE artifact_registry SET category = 'MEDIA'
            WHERE category IN ('Media & Pictures', 'Media');

            UPDATE artifact_registry SET category = 'DOCUMENTS'
            WHERE category IN ('Documents');

            UPDATE artifact_registry SET category = 'MALWARE & YARA'
            WHERE category IN ('Malware & Threat Hunting', 'Malware & YARA');

            UPDATE artifact_registry SET category = 'REFINED RESULTS'
            WHERE category IN ('Refined Results');

            DELETE FROM artifact_registry
            WHERE artifact_id IN ('browser_history', 'browser_downloads', 'browser_logins')
               OR table_name IN ('parsed_browser_history', 'parsed_browser_downloads', 'parsed_browser_logins');
        """)
    except Exception as mig_ex:
        print(f"[Schema] Warning migrating categories: {mig_ex}")

    # 3. Pass 1: Create all tables first
    for entry in MASTER_ARTIFACT_CATALOG:
        if not entry["table_name"].startswith("view_"):
            try:
                cursor.execute(entry["ddl"])
            except Exception as ddl_ex:
                print(f"[Schema] Warning executing DDL for table {entry['table_name']}: {ddl_ex}")

    # Pass 2: Create all views once underlying tables exist
    for entry in MASTER_ARTIFACT_CATALOG:
        if entry["table_name"].startswith("view_"):
            try:
                cursor.execute(entry["ddl"])
            except Exception as ddl_ex:
                print(f"[Schema] Warning executing DDL for view {entry['table_name']}: {ddl_ex}")

    # Pass 3: Pre-populate artifact_registry
    for entry in MASTER_ARTIFACT_CATALOG:
        art_id = entry["artifact_id"]
        cat = entry["category"]
        disp = entry["display_name"]
        tbl = entry["table_name"]
        src = entry["source_tool"]
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
                [art_id, cat, disp, tbl, src],
            )
        except Exception as reg_ex:
            print(f"[Schema] Warning populating artifact_registry for {art_id}: {reg_ex}")

    # 4. Synchronize views, granular tables, and live row counts
    sync_artifact_registry_counts(conn, case_id=case_id)


def verify_core_tables(conn: duckdb.DuckDBPyConnection) -> List[str]:
    """
    Query the DuckDB information schema and return a list of core tables that exist.
    """
    existing_tables = [
        row[0]
        for row in conn.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
        ).fetchall()
    ]
    return [t for t in CORE_TABLES if t in existing_tables]
