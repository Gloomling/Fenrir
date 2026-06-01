# fenrir/database/schema.py
#
# SQLite schema definitions for the Fenrir offline intelligence database.
#
# Tables:
#   Core vulnerability:
#     cves              — NVD CVE records with CVSS v2/v3
#     cpe_matches       — Product/version to CVE mappings
#     kev               — CISA Known Exploited Vulnerabilities
#     epss              — EPSS daily exploit probability scores
#     cwe               — MITRE CWE weakness definitions
#     capec             — MITRE CAPEC attack patterns
#
#   Exploit intelligence:
#     exploits          — Exploit-DB source exploit index
#     shellcodes        — Exploit-DB shellcode index
#
#   Adversary intelligence:
#     attack_techniques — MITRE ATT&CK techniques (Enterprise + ICS + Mobile)
#     attack_groups     — MITRE ATT&CK threat actor groups
#     attack_software   — MITRE ATT&CK tools and malware
#     attack_mitigations— MITRE ATT&CK mitigations
#
#   Threat intelligence:
#     ip_reputation     — Known malicious IPs (Emerging Threats, Spamhaus, etc.)
#     hash_reputation   — Malware hashes (abuse.ch MalwareBazaar)
#     ioc_urls          — Malicious URLs (URLhaus)
#     ioc_threatfox     — IOCs from ThreatFox (C2, domains, hashes)
#     c2_botnet         — Active C2/botnet infrastructure (Feodo Tracker)
#
#   Scanning intelligence:
#     nuclei_templates  — Nuclei template metadata index
#     default_creds     — Default credentials (applications/services)
#     iot_default_creds — Default credentials (IoT/ICS devices)
#     ghdb              — Google Hacking Database dork queries
#     waf_signatures    — WAF fingerprint signatures
#     wordlist_index    — Index of available wordlist files on disk
#
#   Network intelligence:
#     asn_data          — IP-to-ASN mappings
#     tor_exits         — Current Tor exit nodes
#     iana_ports        — IANA official port/protocol assignments
#
#   Compliance / reporting:
#     owasp_findings    — OWASP Top 10 finding templates
#
#   Metadata:
#     db_meta           — Build timestamps, counts, schema version

SCHEMA_VERSION = "3.0.0"

# ===========================================================================
# CORE METADATA
# ===========================================================================

SQL_CREATE_DB_META = """
CREATE TABLE IF NOT EXISTS db_meta (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
"""

# ===========================================================================
# CVE / NVD
# ===========================================================================

SQL_CREATE_CVES = """
CREATE TABLE IF NOT EXISTS cves (
    cve_id              TEXT PRIMARY KEY,
    published           TEXT,
    modified            TEXT,
    description         TEXT,
    cvss_v3_score       REAL,
    cvss_v3_severity    TEXT,
    cvss_v3_vector      TEXT,
    cvss_v2_score       REAL,
    cvss_v2_severity    TEXT,
    cvss_v2_vector      TEXT,
    epss_score          REAL,
    epss_percentile     REAL,
    kev_date_added      TEXT,
    kev_required_action TEXT,
    cpe_matches         TEXT,
    ref_urls            TEXT,
    cwe_ids             TEXT,
    assigner            TEXT
);
"""

SQL_CREATE_CVES_FTS = """
CREATE VIRTUAL TABLE IF NOT EXISTS cves_fts
USING fts5(
    cve_id, description,
    content='cves', content_rowid='rowid'
);
"""

SQL_CREATE_CVES_FTS_INSERT_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS cves_ai AFTER INSERT ON cves BEGIN
    INSERT INTO cves_fts(rowid, cve_id, description)
    VALUES (new.rowid, new.cve_id, new.description);
END;
"""

SQL_CREATE_CVES_FTS_DELETE_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS cves_ad AFTER DELETE ON cves BEGIN
    INSERT INTO cves_fts(cves_fts, rowid, cve_id, description)
    VALUES ('delete', old.rowid, old.cve_id, old.description);
END;
"""

SQL_CREATE_CVES_FTS_UPDATE_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS cves_au AFTER UPDATE ON cves BEGIN
    INSERT INTO cves_fts(cves_fts, rowid, cve_id, description)
    VALUES ('delete', old.rowid, old.cve_id, old.description);
    INSERT INTO cves_fts(rowid, cve_id, description)
    VALUES (new.rowid, new.cve_id, new.description);
END;
"""

SQL_CREATE_CVES_SCORE_INDEX     = "CREATE INDEX IF NOT EXISTS idx_cves_score     ON cves (cvss_v3_score DESC);"
SQL_CREATE_CVES_PUBLISHED_INDEX = "CREATE INDEX IF NOT EXISTS idx_cves_published ON cves (published DESC);"
SQL_CREATE_CVES_SEVERITY_INDEX  = "CREATE INDEX IF NOT EXISTS idx_cves_severity  ON cves (cvss_v3_severity);"
SQL_CREATE_CVES_EPSS_INDEX      = "CREATE INDEX IF NOT EXISTS idx_cves_epss      ON cves (epss_score DESC);"
SQL_CREATE_CVES_KEV_INDEX       = "CREATE INDEX IF NOT EXISTS idx_cves_kev       ON cves (kev_date_added);"

SQL_CREATE_CPE_MATCHES = """
CREATE TABLE IF NOT EXISTS cpe_matches (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    cpe_string  TEXT NOT NULL,
    cve_id      TEXT NOT NULL,
    vulnerable  INTEGER DEFAULT 1,
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
);
"""

SQL_CREATE_CPE_INDEX     = "CREATE INDEX IF NOT EXISTS idx_cpe_string ON cpe_matches (cpe_string);"
SQL_CREATE_CPE_CVE_INDEX = "CREATE INDEX IF NOT EXISTS idx_cpe_cve_id ON cpe_matches (cve_id);"

SQL_CREATE_KEV = """
CREATE TABLE IF NOT EXISTS kev (
    cve_id              TEXT PRIMARY KEY,
    vendor_project      TEXT,
    product             TEXT,
    vulnerability_name  TEXT,
    date_added          TEXT,
    short_description   TEXT,
    required_action     TEXT,
    due_date            TEXT,
    known_ransomware    TEXT,
    notes               TEXT
);
"""

SQL_CREATE_KEV_DATE_INDEX    = "CREATE INDEX IF NOT EXISTS idx_kev_date    ON kev (date_added DESC);"
SQL_CREATE_KEV_PRODUCT_INDEX = "CREATE INDEX IF NOT EXISTS idx_kev_product ON kev (product);"

SQL_CREATE_EPSS = """
CREATE TABLE IF NOT EXISTS epss (
    cve_id      TEXT PRIMARY KEY,
    score       REAL NOT NULL,
    percentile  REAL NOT NULL,
    date        TEXT NOT NULL
);
"""

SQL_CREATE_EPSS_SCORE_INDEX = "CREATE INDEX IF NOT EXISTS idx_epss_score ON epss (score DESC);"

SQL_CREATE_CWE = """
CREATE TABLE IF NOT EXISTS cwe (
    cwe_id          TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    abstraction     TEXT,
    description     TEXT,
    extended_desc   TEXT,
    likelihood      TEXT,
    consequences    TEXT,
    mitigations     TEXT,
    related_cwes    TEXT,
    platforms       TEXT
);
"""

SQL_CREATE_CWE_FTS = """
CREATE VIRTUAL TABLE IF NOT EXISTS cwe_fts
USING fts5(
    cwe_id, name, description,
    content='cwe', content_rowid='rowid'
);
"""

SQL_CREATE_CWE_FTS_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS cwe_ai AFTER INSERT ON cwe BEGIN
    INSERT INTO cwe_fts(rowid, cwe_id, name, description)
    VALUES (new.rowid, new.cwe_id, new.name, new.description);
END;
"""

SQL_CREATE_CAPEC = """
CREATE TABLE IF NOT EXISTS capec (
    capec_id        TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    abstraction     TEXT,
    description     TEXT,
    extended_desc   TEXT,
    likelihood      TEXT,
    severity        TEXT,
    prerequisites   TEXT,
    skills_required TEXT,
    mitigations     TEXT,
    related_cwes    TEXT,
    related_capecs  TEXT,
    attack_steps    TEXT
);
"""

SQL_CREATE_CAPEC_FTS = """
CREATE VIRTUAL TABLE IF NOT EXISTS capec_fts
USING fts5(
    capec_id, name, description,
    content='capec', content_rowid='rowid'
);
"""

SQL_CREATE_CAPEC_FTS_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS capec_ai AFTER INSERT ON capec BEGIN
    INSERT INTO capec_fts(rowid, capec_id, name, description)
    VALUES (new.rowid, new.capec_id, new.name, new.description);
END;
"""

# ===========================================================================
# EXPLOIT TABLES
# ===========================================================================

SQL_CREATE_EXPLOITS = """
CREATE TABLE IF NOT EXISTS exploits (
    exploit_id      INTEGER PRIMARY KEY,
    title           TEXT NOT NULL,
    file_path       TEXT NOT NULL,
    type            TEXT,
    platform        TEXT,
    date_published  TEXT,
    author          TEXT,
    verified        INTEGER DEFAULT 0,
    cve_ids         TEXT,
    edb_url         TEXT,
    description     TEXT,
    port            INTEGER,
    tags            TEXT
);
"""

SQL_CREATE_EXPLOITS_FTS = """
CREATE VIRTUAL TABLE IF NOT EXISTS exploits_fts
USING fts5(
    exploit_id UNINDEXED, title, description, platform, type,
    content='exploits', content_rowid='rowid'
);
"""

SQL_CREATE_EXPLOITS_FTS_INSERT_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS exploits_ai AFTER INSERT ON exploits BEGIN
    INSERT INTO exploits_fts(rowid, exploit_id, title, description, platform, type)
    VALUES (new.rowid, new.exploit_id, new.title, new.description, new.platform, new.type);
END;
"""

SQL_CREATE_EXPLOITS_FTS_DELETE_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS exploits_ad AFTER DELETE ON exploits BEGIN
    INSERT INTO exploits_fts(exploits_fts, rowid, exploit_id, title, description, platform, type)
    VALUES ('delete', old.rowid, old.exploit_id, old.title, old.description, old.platform, old.type);
END;
"""

SQL_CREATE_EXPLOITS_PLATFORM_INDEX = "CREATE INDEX IF NOT EXISTS idx_exploits_platform ON exploits (platform);"
SQL_CREATE_EXPLOITS_TYPE_INDEX     = "CREATE INDEX IF NOT EXISTS idx_exploits_type     ON exploits (type);"
SQL_CREATE_EXPLOITS_VERIFIED_INDEX = "CREATE INDEX IF NOT EXISTS idx_exploits_verified ON exploits (verified);"

SQL_CREATE_SHELLCODES = """
CREATE TABLE IF NOT EXISTS shellcodes (
    shellcode_id    INTEGER PRIMARY KEY,
    title           TEXT NOT NULL,
    file_path       TEXT NOT NULL,
    type            TEXT,
    platform        TEXT,
    date_published  TEXT,
    author          TEXT,
    verified        INTEGER DEFAULT 0,
    edb_url         TEXT,
    description     TEXT,
    architecture    TEXT
);
"""

SQL_CREATE_SHELLCODES_FTS = """
CREATE VIRTUAL TABLE IF NOT EXISTS shellcodes_fts
USING fts5(
    shellcode_id UNINDEXED, title, description, platform, architecture,
    content='shellcodes', content_rowid='rowid'
);
"""

SQL_CREATE_SHELLCODES_FTS_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS shellcodes_ai AFTER INSERT ON shellcodes BEGIN
    INSERT INTO shellcodes_fts(rowid, shellcode_id, title, description, platform, architecture)
    VALUES (new.rowid, new.shellcode_id, new.title, new.description, new.platform, new.architecture);
END;
"""

SQL_CREATE_SHELLCODES_PLATFORM_INDEX = "CREATE INDEX IF NOT EXISTS idx_shellcodes_platform ON shellcodes (platform);"
SQL_CREATE_SHELLCODES_ARCH_INDEX     = "CREATE INDEX IF NOT EXISTS idx_shellcodes_arch     ON shellcodes (architecture);"

# ===========================================================================
# ATT&CK
# ===========================================================================

SQL_CREATE_ATTACK_TECHNIQUES = """
CREATE TABLE IF NOT EXISTS attack_techniques (
    technique_id        TEXT PRIMARY KEY,
    name                TEXT NOT NULL,
    tactic              TEXT,
    domain              TEXT,
    description         TEXT,
    detection           TEXT,
    mitigations         TEXT,
    data_sources        TEXT,
    platforms           TEXT,
    permissions         TEXT,
    defenses_bypassed   TEXT,
    is_subtechnique     INTEGER DEFAULT 0,
    parent_id           TEXT,
    url                 TEXT,
    version             TEXT
);
"""

SQL_CREATE_ATTACK_TECHNIQUES_FTS = """
CREATE VIRTUAL TABLE IF NOT EXISTS attack_techniques_fts
USING fts5(
    technique_id, name, tactic, description,
    content='attack_techniques', content_rowid='rowid'
);
"""

SQL_CREATE_ATTACK_TECHNIQUES_FTS_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS attack_techniques_ai AFTER INSERT ON attack_techniques BEGIN
    INSERT INTO attack_techniques_fts(rowid, technique_id, name, tactic, description)
    VALUES (new.rowid, new.technique_id, new.name, new.tactic, new.description);
END;
"""

SQL_CREATE_ATTACK_TACTIC_INDEX = "CREATE INDEX IF NOT EXISTS idx_attack_tactic  ON attack_techniques (tactic);"
SQL_CREATE_ATTACK_DOMAIN_INDEX = "CREATE INDEX IF NOT EXISTS idx_attack_domain  ON attack_techniques (domain);"
SQL_CREATE_ATTACK_PARENT_INDEX = "CREATE INDEX IF NOT EXISTS idx_attack_parent  ON attack_techniques (parent_id);"

SQL_CREATE_ATTACK_GROUPS = """
CREATE TABLE IF NOT EXISTS attack_groups (
    group_id        TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    aliases         TEXT,
    description     TEXT,
    country         TEXT,
    techniques_used TEXT,
    software_used   TEXT,
    url             TEXT
);
"""

SQL_CREATE_ATTACK_SOFTWARE = """
CREATE TABLE IF NOT EXISTS attack_software (
    software_id     TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    software_type   TEXT,
    aliases         TEXT,
    description     TEXT,
    platforms       TEXT,
    techniques_used TEXT,
    groups_using    TEXT,
    url             TEXT
);
"""

SQL_CREATE_ATTACK_MITIGATIONS = """
CREATE TABLE IF NOT EXISTS attack_mitigations (
    mitigation_id   TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    description     TEXT,
    techniques      TEXT,
    url             TEXT
);
"""

# ===========================================================================
# THREAT INTELLIGENCE
# ===========================================================================

SQL_CREATE_IP_REPUTATION = """
CREATE TABLE IF NOT EXISTS ip_reputation (
    ip_address  TEXT PRIMARY KEY,
    category    TEXT,
    source      TEXT,
    added_date  TEXT,
    notes       TEXT,
    country     TEXT,
    asn         TEXT
);
"""

SQL_CREATE_IP_SOURCE_INDEX   = "CREATE INDEX IF NOT EXISTS idx_ip_source   ON ip_reputation (source);"
SQL_CREATE_IP_CATEGORY_INDEX = "CREATE INDEX IF NOT EXISTS idx_ip_category ON ip_reputation (category);"

SQL_CREATE_HASH_REPUTATION = """
CREATE TABLE IF NOT EXISTS hash_reputation (
    hash_sha256     TEXT PRIMARY KEY,
    hash_md5        TEXT,
    hash_sha1       TEXT,
    malware_family  TEXT,
    malware_type    TEXT,
    source          TEXT,
    added_date      TEXT,
    signature       TEXT
);
"""

SQL_CREATE_HASH_MD5_INDEX  = "CREATE INDEX IF NOT EXISTS idx_hash_md5  ON hash_reputation (hash_md5);"
SQL_CREATE_HASH_SHA1_INDEX = "CREATE INDEX IF NOT EXISTS idx_hash_sha1 ON hash_reputation (hash_sha1);"

SQL_CREATE_IOC_URLS = """
CREATE TABLE IF NOT EXISTS ioc_urls (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    url         TEXT UNIQUE NOT NULL,
    host        TEXT,
    ip_address  TEXT,
    url_status  TEXT,
    date_added  TEXT,
    threat      TEXT,
    tags        TEXT,
    reporter    TEXT,
    urlhaus_id  TEXT
);
"""

SQL_CREATE_IOC_URLS_HOST_INDEX   = "CREATE INDEX IF NOT EXISTS idx_ioc_urls_host   ON ioc_urls (host);"
SQL_CREATE_IOC_URLS_IP_INDEX     = "CREATE INDEX IF NOT EXISTS idx_ioc_urls_ip     ON ioc_urls (ip_address);"
SQL_CREATE_IOC_URLS_THREAT_INDEX = "CREATE INDEX IF NOT EXISTS idx_ioc_urls_threat ON ioc_urls (threat);"

SQL_CREATE_IOC_THREATFOX = """
CREATE TABLE IF NOT EXISTS ioc_threatfox (
    ioc_id          INTEGER PRIMARY KEY,
    ioc_value       TEXT NOT NULL,
    ioc_type        TEXT,
    threat_type     TEXT,
    malware         TEXT,
    malware_alias   TEXT,
    confidence      INTEGER,
    date_added      TEXT,
    reporter        TEXT,
    tags            TEXT,
    reference       TEXT
);
"""

SQL_CREATE_IOC_THREATFOX_VALUE_INDEX   = "CREATE INDEX IF NOT EXISTS idx_threatfox_value   ON ioc_threatfox (ioc_value);"
SQL_CREATE_IOC_THREATFOX_TYPE_INDEX    = "CREATE INDEX IF NOT EXISTS idx_threatfox_type    ON ioc_threatfox (ioc_type);"
SQL_CREATE_IOC_THREATFOX_MALWARE_INDEX = "CREATE INDEX IF NOT EXISTS idx_threatfox_malware ON ioc_threatfox (malware);"

SQL_CREATE_C2_BOTNET = """
CREATE TABLE IF NOT EXISTS c2_botnet (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address  TEXT NOT NULL,
    port        INTEGER,
    status      TEXT,
    malware     TEXT,
    first_seen  TEXT,
    last_seen   TEXT,
    country     TEXT,
    asn         TEXT,
    source      TEXT
);
"""

SQL_CREATE_C2_IP_INDEX      = "CREATE INDEX IF NOT EXISTS idx_c2_ip      ON c2_botnet (ip_address);"
SQL_CREATE_C2_MALWARE_INDEX = "CREATE INDEX IF NOT EXISTS idx_c2_malware ON c2_botnet (malware);"

# ===========================================================================
# SCANNING INTELLIGENCE
# ===========================================================================

SQL_CREATE_NUCLEI_TEMPLATES = """
CREATE TABLE IF NOT EXISTS nuclei_templates (
    template_id     TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    file_path       TEXT NOT NULL,
    severity        TEXT,
    category        TEXT,
    tags            TEXT,
    description     TEXT,
    cve_ids         TEXT,
    cwe_ids         TEXT,
    author          TEXT,
    is_kev          INTEGER DEFAULT 0,
    protocol        TEXT,
    date_modified   TEXT
);
"""

SQL_CREATE_NUCLEI_FTS = """
CREATE VIRTUAL TABLE IF NOT EXISTS nuclei_fts
USING fts5(
    template_id, name, description, tags,
    content='nuclei_templates', content_rowid='rowid'
);
"""

SQL_CREATE_NUCLEI_FTS_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS nuclei_ai AFTER INSERT ON nuclei_templates BEGIN
    INSERT INTO nuclei_fts(rowid, template_id, name, description, tags)
    VALUES (new.rowid, new.template_id, new.name, new.description, new.tags);
END;
"""

SQL_CREATE_NUCLEI_SEVERITY_INDEX = "CREATE INDEX IF NOT EXISTS idx_nuclei_severity ON nuclei_templates (severity);"
SQL_CREATE_NUCLEI_CATEGORY_INDEX = "CREATE INDEX IF NOT EXISTS idx_nuclei_category ON nuclei_templates (category);"
SQL_CREATE_NUCLEI_KEV_INDEX      = "CREATE INDEX IF NOT EXISTS idx_nuclei_kev      ON nuclei_templates (is_kev);"

SQL_CREATE_DEFAULT_CREDS = """
CREATE TABLE IF NOT EXISTS default_creds (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    vendor      TEXT,
    product     TEXT,
    device_type TEXT,
    username    TEXT,
    password    TEXT,
    notes       TEXT,
    source      TEXT
);
"""

SQL_CREATE_DEFAULT_CREDS_FTS = """
CREATE VIRTUAL TABLE IF NOT EXISTS default_creds_fts
USING fts5(
    vendor, product, device_type,
    content='default_creds', content_rowid='rowid'
);
"""

SQL_CREATE_DEFAULT_CREDS_FTS_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS default_creds_ai AFTER INSERT ON default_creds BEGIN
    INSERT INTO default_creds_fts(rowid, vendor, product, device_type)
    VALUES (new.rowid, new.vendor, new.product, new.device_type);
END;
"""

SQL_CREATE_DEFAULT_CREDS_VENDOR_INDEX = "CREATE INDEX IF NOT EXISTS idx_creds_vendor ON default_creds (vendor);"
SQL_CREATE_DEFAULT_CREDS_TYPE_INDEX   = "CREATE INDEX IF NOT EXISTS idx_creds_type   ON default_creds (device_type);"

SQL_CREATE_IOT_DEFAULT_CREDS = """
CREATE TABLE IF NOT EXISTS iot_default_creds (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    vendor      TEXT NOT NULL,
    model       TEXT,
    device_type TEXT,
    service     TEXT,
    port        INTEGER,
    username    TEXT,
    password    TEXT,
    notes       TEXT
);
"""

SQL_CREATE_IOT_CREDS_FTS = """
CREATE VIRTUAL TABLE IF NOT EXISTS iot_creds_fts
USING fts5(
    vendor, model, device_type,
    content='iot_default_creds', content_rowid='rowid'
);
"""

SQL_CREATE_IOT_CREDS_FTS_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS iot_creds_ai AFTER INSERT ON iot_default_creds BEGIN
    INSERT INTO iot_creds_fts(rowid, vendor, model, device_type)
    VALUES (new.rowid, new.vendor, new.model, new.device_type);
END;
"""

SQL_CREATE_IOT_VENDOR_INDEX = "CREATE INDEX IF NOT EXISTS idx_iot_vendor ON iot_default_creds (vendor);"
SQL_CREATE_IOT_TYPE_INDEX   = "CREATE INDEX IF NOT EXISTS idx_iot_type   ON iot_default_creds (device_type);"

SQL_CREATE_GHDB = """
CREATE TABLE IF NOT EXISTS ghdb (
    ghdb_id     INTEGER PRIMARY KEY,
    category    TEXT NOT NULL,
    query       TEXT NOT NULL,
    description TEXT,
    date_added  TEXT,
    author      TEXT,
    url         TEXT
);
"""

SQL_CREATE_GHDB_FTS = """
CREATE VIRTUAL TABLE IF NOT EXISTS ghdb_fts
USING fts5(
    ghdb_id UNINDEXED, category, query, description,
    content='ghdb', content_rowid='rowid'
);
"""

SQL_CREATE_GHDB_FTS_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS ghdb_ai AFTER INSERT ON ghdb BEGIN
    INSERT INTO ghdb_fts(rowid, ghdb_id, category, query, description)
    VALUES (new.rowid, new.ghdb_id, new.category, new.query, new.description);
END;
"""

SQL_CREATE_GHDB_CATEGORY_INDEX = "CREATE INDEX IF NOT EXISTS idx_ghdb_category ON ghdb (category);"

SQL_CREATE_WAF_SIGNATURES = """
CREATE TABLE IF NOT EXISTS waf_signatures (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    waf_name        TEXT NOT NULL,
    indicator_type  TEXT,
    indicator_value TEXT,
    confidence      INTEGER DEFAULT 100,
    source          TEXT
);
"""

SQL_CREATE_WAF_NAME_INDEX = "CREATE INDEX IF NOT EXISTS idx_waf_name ON waf_signatures (waf_name);"

SQL_CREATE_WORDLIST_INDEX = """
CREATE TABLE IF NOT EXISTS wordlist_index (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL,
    file_path       TEXT NOT NULL,
    category        TEXT,
    description     TEXT,
    line_count      INTEGER,
    file_size_bytes INTEGER,
    source          TEXT,
    tags            TEXT
);
"""

SQL_CREATE_WORDLIST_CATEGORY_INDEX = "CREATE INDEX IF NOT EXISTS idx_wordlist_category ON wordlist_index (category);"

# ===========================================================================
# NETWORK INTELLIGENCE
# ===========================================================================

SQL_CREATE_ASN_DATA = """
CREATE TABLE IF NOT EXISTS asn_data (
    ip_from     TEXT NOT NULL,
    ip_to       TEXT NOT NULL,
    asn         TEXT NOT NULL,
    country     TEXT,
    org_name    TEXT,
    PRIMARY KEY (ip_from, asn)
);
"""

SQL_CREATE_ASN_ASN_INDEX = "CREATE INDEX IF NOT EXISTS idx_asn_asn ON asn_data (asn);"

SQL_CREATE_TOR_EXITS = """
CREATE TABLE IF NOT EXISTS tor_exits (
    ip_address  TEXT PRIMARY KEY,
    added_date  TEXT
);
"""

SQL_CREATE_IANA_PORTS = """
CREATE TABLE IF NOT EXISTS iana_ports (
    port        INTEGER NOT NULL,
    protocol    TEXT NOT NULL,
    service     TEXT,
    description TEXT,
    PRIMARY KEY (port, protocol)
);
"""

SQL_CREATE_IANA_SERVICE_INDEX = "CREATE INDEX IF NOT EXISTS idx_iana_service ON iana_ports (service);"

# ===========================================================================
# COMPLIANCE / REPORTING
# ===========================================================================

SQL_CREATE_OWASP_FINDINGS = """
CREATE TABLE IF NOT EXISTS owasp_findings (
    finding_id  TEXT PRIMARY KEY,
    category    TEXT NOT NULL,
    owasp_year  INTEGER,
    title       TEXT NOT NULL,
    description TEXT,
    risk_rating TEXT,
    likelihood  TEXT,
    impact      TEXT,
    remediation TEXT,
    ref_urls    TEXT,
    cwe_ids     TEXT
);
"""

# ===========================================================================
# GROUPED DDL LIST
# ===========================================================================

ALL_CREATE_STATEMENTS = [
    # Metadata
    SQL_CREATE_DB_META,
    # CVE / NVD
    SQL_CREATE_CVES, SQL_CREATE_CPE_MATCHES,
    SQL_CREATE_KEV, SQL_CREATE_EPSS,
    SQL_CREATE_CWE, SQL_CREATE_CAPEC,
    # Exploits
    SQL_CREATE_EXPLOITS, SQL_CREATE_SHELLCODES,
    # ATT&CK
    SQL_CREATE_ATTACK_TECHNIQUES, SQL_CREATE_ATTACK_GROUPS,
    SQL_CREATE_ATTACK_SOFTWARE, SQL_CREATE_ATTACK_MITIGATIONS,
    # Threat intel
    SQL_CREATE_IP_REPUTATION, SQL_CREATE_HASH_REPUTATION,
    SQL_CREATE_IOC_URLS, SQL_CREATE_IOC_THREATFOX, SQL_CREATE_C2_BOTNET,
    # Scanning intelligence
    SQL_CREATE_NUCLEI_TEMPLATES,
    SQL_CREATE_DEFAULT_CREDS, SQL_CREATE_IOT_DEFAULT_CREDS,
    SQL_CREATE_GHDB, SQL_CREATE_WAF_SIGNATURES, SQL_CREATE_WORDLIST_INDEX,
    # Network
    SQL_CREATE_ASN_DATA, SQL_CREATE_TOR_EXITS, SQL_CREATE_IANA_PORTS,
    # Compliance
    SQL_CREATE_OWASP_FINDINGS,
    # FTS virtual tables
    SQL_CREATE_CVES_FTS, SQL_CREATE_CWE_FTS, SQL_CREATE_CAPEC_FTS,
    SQL_CREATE_EXPLOITS_FTS, SQL_CREATE_SHELLCODES_FTS,
    SQL_CREATE_ATTACK_TECHNIQUES_FTS,
    SQL_CREATE_NUCLEI_FTS,
    SQL_CREATE_DEFAULT_CREDS_FTS, SQL_CREATE_IOT_CREDS_FTS,
    SQL_CREATE_GHDB_FTS,
    # FTS triggers
    SQL_CREATE_CVES_FTS_INSERT_TRIGGER,
    SQL_CREATE_CVES_FTS_DELETE_TRIGGER,
    SQL_CREATE_CVES_FTS_UPDATE_TRIGGER,
    SQL_CREATE_CWE_FTS_TRIGGER, SQL_CREATE_CAPEC_FTS_TRIGGER,
    SQL_CREATE_EXPLOITS_FTS_INSERT_TRIGGER,
    SQL_CREATE_EXPLOITS_FTS_DELETE_TRIGGER,
    SQL_CREATE_SHELLCODES_FTS_TRIGGER,
    SQL_CREATE_ATTACK_TECHNIQUES_FTS_TRIGGER,
    SQL_CREATE_NUCLEI_FTS_TRIGGER,
    SQL_CREATE_DEFAULT_CREDS_FTS_TRIGGER,
    SQL_CREATE_IOT_CREDS_FTS_TRIGGER,
    SQL_CREATE_GHDB_FTS_TRIGGER,
    # Indexes
    SQL_CREATE_CVES_SCORE_INDEX, SQL_CREATE_CVES_PUBLISHED_INDEX,
    SQL_CREATE_CVES_SEVERITY_INDEX, SQL_CREATE_CVES_EPSS_INDEX,
    SQL_CREATE_CVES_KEV_INDEX,
    SQL_CREATE_CPE_INDEX, SQL_CREATE_CPE_CVE_INDEX,
    SQL_CREATE_KEV_DATE_INDEX, SQL_CREATE_KEV_PRODUCT_INDEX,
    SQL_CREATE_EPSS_SCORE_INDEX,
    SQL_CREATE_EXPLOITS_PLATFORM_INDEX, SQL_CREATE_EXPLOITS_TYPE_INDEX,
    SQL_CREATE_EXPLOITS_VERIFIED_INDEX,
    SQL_CREATE_SHELLCODES_PLATFORM_INDEX, SQL_CREATE_SHELLCODES_ARCH_INDEX,
    SQL_CREATE_ATTACK_TACTIC_INDEX, SQL_CREATE_ATTACK_DOMAIN_INDEX,
    SQL_CREATE_ATTACK_PARENT_INDEX,
    SQL_CREATE_IP_SOURCE_INDEX, SQL_CREATE_IP_CATEGORY_INDEX,
    SQL_CREATE_HASH_MD5_INDEX, SQL_CREATE_HASH_SHA1_INDEX,
    SQL_CREATE_IOC_URLS_HOST_INDEX, SQL_CREATE_IOC_URLS_IP_INDEX,
    SQL_CREATE_IOC_URLS_THREAT_INDEX,
    SQL_CREATE_IOC_THREATFOX_VALUE_INDEX, SQL_CREATE_IOC_THREATFOX_TYPE_INDEX,
    SQL_CREATE_IOC_THREATFOX_MALWARE_INDEX,
    SQL_CREATE_C2_IP_INDEX, SQL_CREATE_C2_MALWARE_INDEX,
    SQL_CREATE_NUCLEI_SEVERITY_INDEX, SQL_CREATE_NUCLEI_CATEGORY_INDEX,
    SQL_CREATE_NUCLEI_KEV_INDEX,
    SQL_CREATE_DEFAULT_CREDS_VENDOR_INDEX, SQL_CREATE_DEFAULT_CREDS_TYPE_INDEX,
    SQL_CREATE_IOT_VENDOR_INDEX, SQL_CREATE_IOT_TYPE_INDEX,
    SQL_CREATE_GHDB_CATEGORY_INDEX,
    SQL_CREATE_WAF_NAME_INDEX,
    SQL_CREATE_WORDLIST_CATEGORY_INDEX,
    SQL_CREATE_ASN_ASN_INDEX,
    SQL_CREATE_IANA_SERVICE_INDEX,
]

# ===========================================================================
# META KEYS
# ===========================================================================

META_SCHEMA_VERSION          = "schema_version"
META_NVD_LAST_UPDATED        = "nvd_last_updated"
META_NVD_BUILD_TYPE          = "nvd_build_type"
META_NVD_YEAR_START          = "nvd_year_start"
META_NVD_CVE_COUNT           = "nvd_cve_count"
META_EDB_LAST_UPDATED        = "exploitdb_last_updated"
META_EDB_COMMIT              = "exploitdb_last_commit"
META_EDB_EXPLOIT_COUNT       = "exploitdb_exploit_count"
META_EDB_SHELLCODE_COUNT     = "exploitdb_shellcode_count"
META_EDB_PAPER_COUNT         = "exploitdb_paper_count"
META_BINSPLOITS_COMMIT       = "binsploits_last_commit"
META_KEV_LAST_UPDATED        = "kev_last_updated"
META_KEV_COUNT               = "kev_count"
META_EPSS_LAST_UPDATED       = "epss_last_updated"
META_EPSS_COUNT              = "epss_count"
META_CWE_LAST_UPDATED        = "cwe_last_updated"
META_CWE_COUNT               = "cwe_count"
META_CAPEC_LAST_UPDATED      = "capec_last_updated"
META_CAPEC_COUNT             = "capec_count"
META_ATTACK_LAST_UPDATED     = "attack_last_updated"
META_ATTACK_VERSION          = "attack_version"
META_ATTACK_TECHNIQUE_COUNT  = "attack_technique_count"
META_ATTACK_GROUP_COUNT      = "attack_group_count"
META_FEEDS_LAST_UPDATED      = "threat_feeds_last_updated"
META_IP_REP_COUNT            = "ip_reputation_count"
META_HASH_REP_COUNT          = "hash_reputation_count"
META_IOC_URL_COUNT           = "ioc_url_count"
META_IOC_THREATFOX_COUNT     = "ioc_threatfox_count"
META_C2_COUNT                = "c2_botnet_count"
META_NUCLEI_LAST_UPDATED     = "nuclei_last_updated"
META_NUCLEI_TEMPLATE_COUNT   = "nuclei_template_count"
META_DEFAULT_CREDS_COUNT     = "default_creds_count"
META_IOT_CREDS_COUNT         = "iot_creds_count"
META_GHDB_COUNT              = "ghdb_count"
META_WAF_SIG_COUNT           = "waf_signature_count"
META_WORDLISTS_LAST_UPDATED  = "wordlists_last_updated"
META_WORDLISTS_COUNT         = "wordlists_count"
META_SECLISTS_COMMIT         = "seclists_last_commit"
META_PAYLOADS_COMMIT         = "payloads_last_commit"
META_ASN_LAST_UPDATED        = "asn_last_updated"
META_ASN_COUNT               = "asn_count"
META_TOR_LAST_UPDATED        = "tor_last_updated"
META_TOR_COUNT               = "tor_count"
META_IANA_LAST_UPDATED       = "iana_last_updated"
META_IANA_PORT_COUNT         = "iana_port_count"
META_BUILD_DURATION          = "last_build_duration_seconds"
META_BUILD_TIER              = "build_tier"

# ===========================================================================
# BUILD TIERS
# ===========================================================================

BUILD_TIERS = {
    "core": {
        "description": "Standard pentest — quick install (~4.5 GB)",
        "sources": [
            "nvd_lite", "exploitdb_source", "exploitdb_shellcodes",
            "kev", "epss", "cwe", "capec", "attack",
            "seclists", "default_creds", "iot_creds",
            "ghdb", "nuclei", "threat_feeds", "hash_feeds",
            "iana_ports", "owasp",
        ],
    },
    "standard": {
        "description": "Full pentest + red team (~8 GB)",
        "sources": [
            "nvd_full", "exploitdb_source", "exploitdb_shellcodes",
            "exploitdb_bins", "exploitdb_papers",
            "kev", "epss", "cwe", "capec", "attack",
            "seclists", "payloads_all_things", "fuzzdb",
            "default_creds", "iot_creds", "ghdb", "nuclei",
            "threat_feeds", "hash_feeds", "ioc_urls", "threatfox",
            "c2_botnet", "waf_signatures",
            "asn_data", "tor_exits", "iana_ports", "owasp",
        ],
    },
    "full": {
        "description": "Full red team + offline cracking (~25 GB+)",
        "sources": [
            "nvd_full", "exploitdb_source", "exploitdb_shellcodes",
            "exploitdb_bins", "exploitdb_papers",
            "kev", "epss", "cwe", "capec", "attack",
            "seclists", "payloads_all_things", "fuzzdb",
            "rockyou", "hibp_passwords",
            "default_creds", "iot_creds", "ghdb", "nuclei",
            "threat_feeds", "hash_feeds", "ioc_urls", "threatfox",
            "c2_botnet", "waf_signatures",
            "asn_data", "tor_exits", "iana_ports", "owasp",
        ],
    },
}
