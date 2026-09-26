import os
import re
import sqlite3
import ipaddress
from datetime import datetime


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

FEEDS_DIR = os.path.join(BASE_DIR, "feeds")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

DATABASE_FILE = os.path.join(
    BASE_DIR,
    "threat_intelligence.db"
)


# ============================================================
# BANNER
# ============================================================

def show_banner():

    print("=" * 65)
    print("       THREAT INTELLIGENCE AGGREGATOR")
    print("=" * 65)
    print("Collecting, validating and analyzing threat indicators")
    print("=" * 65)


# ============================================================
# FOLDER CHECK
# ============================================================

def check_folders():

    os.makedirs(FEEDS_DIR, exist_ok=True)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)


# ============================================================
# DATABASE SETUP
# ============================================================

def setup_database():

    connection = sqlite3.connect(DATABASE_FILE)
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT NOT NULL,
            ioc_type TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            source TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            occurrences INTEGER DEFAULT 1,
            UNIQUE(indicator, ioc_type, source)
        )
    """)

    connection.commit()
    connection.close()

    print("\nDatabase initialized successfully.")
    print(f"Database: {DATABASE_FILE}")


# ============================================================
# READ FEEDS
# ============================================================

def read_feeds():

    all_feeds = []

    for file_name in sorted(os.listdir(FEEDS_DIR)):

        if file_name.endswith(".txt"):

            file_path = os.path.join(
                FEEDS_DIR,
                file_name
            )

            with open(
                file_path,
                "r",
                encoding="utf-8"
            ) as file:

                content = file.read()

            all_feeds.append({
                "source": file_name,
                "content": content
            })

    return all_feeds


# ============================================================
# IOC VALIDATION
# ============================================================

def is_valid_ip(ip):

    try:

        ipaddress.ip_address(ip)

        return True

    except ValueError:

        return False


def is_valid_domain(domain):

    domain = domain.lower().strip()
    domain = domain.rstrip(".")

    pattern = (
        r"^(?=.{1,253}$)"
        r"(?:[a-z0-9]"
        r"(?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"[a-z]{2,63}$"
    )

    return bool(
        re.match(
            pattern,
            domain,
            re.IGNORECASE
        )
    )


def is_valid_hash(value):

    return bool(
        re.fullmatch(
            r"[a-fA-F0-9]{32}|"
            r"[a-fA-F0-9]{40}|"
            r"[a-fA-F0-9]{64}",
            value
        )
    )


# ============================================================
# IOC NORMALIZATION
# ============================================================

def normalize_url(url):

    url = url.strip()
    url = url.rstrip(".,;")

    match = re.match(
        r"^(https?://)([^/]+)(.*)$",
        url,
        re.IGNORECASE
    )

    if match:

        protocol = match.group(1).lower()
        domain = match.group(2).lower()
        path = match.group(3)

        return protocol + domain + path

    return url.lower()


def normalize_domain(domain):

    return domain.strip().lower().rstrip(".,;")


def normalize_hash(value):

    return value.strip().lower()


def normalize_ip(ip):

    return ip.strip()


# ============================================================
# IOC EXTRACTION
# ============================================================

def extract_iocs(text):

    iocs = {
        "ip": [],
        "domain": [],
        "url": [],
        "hash": []
    }

    # ----------------------------
    # URLs
    # ----------------------------

    url_pattern = r"https?://[^\s]+"

    raw_urls = re.findall(
        url_pattern,
        text,
        re.IGNORECASE
    )

    for url in raw_urls:

        normalized = normalize_url(url)

        iocs["url"].append(normalized)

    # ----------------------------
    # IP addresses
    # ----------------------------

    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    raw_ips = re.findall(
        ip_pattern,
        text
    )

    for ip in raw_ips:

        if is_valid_ip(ip):

            normalized = normalize_ip(ip)

            iocs["ip"].append(normalized)

    # ----------------------------
    # Hashes
    # ----------------------------

    hash_pattern = r"\b[a-fA-F0-9]{32,64}\b"

    raw_hashes = re.findall(
        hash_pattern,
        text
    )

    for value in raw_hashes:

        if is_valid_hash(value):

            normalized = normalize_hash(value)

            iocs["hash"].append(normalized)

    # ----------------------------
    # Domains
    # ----------------------------

    domain_pattern = (
        r"\b(?:[a-zA-Z0-9-]+\.)+"
        r"[a-zA-Z]{2,63}\b"
    )

    raw_domains = re.findall(
        domain_pattern,
        text
    )

    for domain in raw_domains:

        normalized = normalize_domain(domain)

        if is_valid_domain(normalized):

            iocs["domain"].append(normalized)

    # ----------------------------
    # Remove duplicates
    # ----------------------------

    for ioc_type in iocs:

        iocs[ioc_type] = sorted(
            set(iocs[ioc_type])
        )

    return iocs


# ============================================================
# RISK LEVEL
# ============================================================

def get_risk_level(ioc_type):

    if ioc_type == "domain":

        return "MEDIUM"

    return "HIGH"


# ============================================================
# NEW / PREVIOUSLY KNOWN IOC DETECTION
# ============================================================

def detect_ioc_history(iocs):

    connection = sqlite3.connect(
        DATABASE_FILE
    )

    cursor = connection.cursor()

    new_iocs = {
        "ip": [],
        "domain": [],
        "url": [],
        "hash": []
    }

    known_iocs = {
        "ip": [],
        "domain": [],
        "url": [],
        "hash": []
    }

    for ioc_type, values in iocs.items():

        for indicator in values:

            cursor.execute("""
                SELECT COUNT(*)
                FROM iocs
                WHERE indicator = ?
                AND ioc_type = ?
            """, (
                indicator,
                ioc_type
            ))

            count = cursor.fetchone()[0]

            if count > 0:

                known_iocs[ioc_type].append(
                    indicator
                )

            else:

                new_iocs[ioc_type].append(
                    indicator
                )

    connection.close()

    return new_iocs, known_iocs


# ============================================================
# DISPLAY IOC HISTORY
# ============================================================

def display_ioc_history(new_iocs, known_iocs):

    new_total = sum(
        len(values)
        for values in new_iocs.values()
    )

    known_total = sum(
        len(values)
        for values in known_iocs.values()
    )

    print("\n" + "=" * 65)
    print("IOC HISTORY ANALYSIS")
    print("=" * 65)

    print(
        f"\nNew IOCs              : {new_total}"
    )

    print(
        f"Previously Known IOCs : {known_total}"
    )

    print("\nNEW IOCs")

    print("-" * 65)

    if new_total == 0:

        print("No new IOCs detected.")

    else:

        for ioc_type, values in new_iocs.items():

            for indicator in values:

                print(
                    f"[NEW {ioc_type.upper()}] "
                    f"{indicator}"
                )

    print("\nPREVIOUSLY KNOWN IOCs")

    print("-" * 65)

    if known_total == 0:

        print("No previously known IOCs detected.")

    else:

        for ioc_type, values in known_iocs.items():

            for indicator in values:

                print(
                    f"[KNOWN {ioc_type.upper()}] "
                    f"{indicator}"
                )


# ============================================================
# SAVE IOCs TO DATABASE
# ============================================================

def save_iocs_to_database(iocs, source):

    connection = sqlite3.connect(
        DATABASE_FILE
    )

    cursor = connection.cursor()

    current_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    for ioc_type, values in iocs.items():

        for indicator in values:

            risk_level = get_risk_level(
                ioc_type
            )

            cursor.execute("""
                SELECT id, occurrences
                FROM iocs
                WHERE indicator = ?
                AND ioc_type = ?
                AND source = ?
            """, (
                indicator,
                ioc_type,
                source
            ))

            existing = cursor.fetchone()

            if existing:

                new_occurrences = existing[1] + 1

                cursor.execute("""
                    UPDATE iocs
                    SET last_seen = ?,
                        occurrences = ?
                    WHERE id = ?
                """, (
                    current_time,
                    new_occurrences,
                    existing[0]
                ))

            else:

                cursor.execute("""
                    INSERT INTO iocs
                    (
                        indicator,
                        ioc_type,
                        risk_level,
                        source,
                        first_seen,
                        last_seen,
                        occurrences
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    indicator,
                    ioc_type,
                    risk_level,
                    source,
                    current_time,
                    current_time,
                    1
                ))

    connection.commit()
    connection.close()


# ============================================================
# DISPLAY IOCs
# ============================================================

def display_iocs(iocs):

    print("\n" + "=" * 65)
    print("EXTRACTED AND VALIDATED IOCs")
    print("=" * 65)

    print(
        f"\nIP Addresses : {len(iocs['ip'])}"
    )

    for ip in iocs["ip"]:

        print(
            f"  [IP]     {ip}"
        )

    print(
        f"\nDomains      : {len(iocs['domain'])}"
    )

    for domain in iocs["domain"]:

        print(
            f"  [DOMAIN] {domain}"
        )

    print(
        f"\nURLs         : {len(iocs['url'])}"
    )

    for url in iocs["url"]:

        print(
            f"  [URL]    {url}"
        )

    print(
        f"\nHashes       : {len(iocs['hash'])}"
    )

    for value in iocs["hash"]:

        print(
            f"  [HASH]   {value}"
        )

    total = sum(
        len(values)
        for values in iocs.values()
    )

    print("\n" + "-" * 65)

    print(
        f"TOTAL UNIQUE VALID IOCs : {total}"
    )

    print("-" * 65)


# ============================================================
# CSV EXPORT
# ============================================================

def save_iocs_to_csv(iocs):

    csv_file = os.path.join(
        OUTPUT_DIR,
        "ioc_data.csv"
    )

    with open(
        csv_file,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            "IOC,Type,Risk Level\n"
        )

        for ioc_type, values in iocs.items():

            for indicator in values:

                risk = get_risk_level(
                    ioc_type
                )

                file.write(
                    f'"{indicator}",'
                    f'{ioc_type},{risk}\n'
                )

    print(
        f"\nCSV saved: {csv_file}"
    )


# ============================================================
# RISK CLASSIFICATION
# ============================================================

def classify_iocs(iocs):

    print("\n" + "=" * 65)
    print("IOC RISK CLASSIFICATION")
    print("=" * 65)

    for ioc_type, values in iocs.items():

        for indicator in values:

            risk = get_risk_level(
                ioc_type
            )

            print(
                f"{indicator:<45} -> {risk}"
            )


# ============================================================
# CROSS-FEED CORRELATION
# ============================================================

def correlate_iocs(iocs):

    print("\n" + "=" * 65)
    print("CROSS-FEED IOC CORRELATION")
    print("=" * 65)

    connection = sqlite3.connect(
        DATABASE_FILE
    )

    cursor = connection.cursor()

    found_correlation = False

    for ioc_type, values in iocs.items():

        for indicator in values:

            cursor.execute("""
                SELECT COUNT(DISTINCT source)
                FROM iocs
                WHERE indicator = ?
                AND ioc_type = ?
            """, (
                indicator,
                ioc_type
            ))

            source_count = cursor.fetchone()[0]

            if source_count > 1:

                found_correlation = True

                print(
                    f"\n{ioc_type.upper()}: "
                    f"{indicator}"
                )

                print(
                    f"Found in "
                    f"{source_count} different feeds"
                )

                print(
                    "⚠️ Correlated threat indicator"
                )

    connection.close()

    if not found_correlation:

        print(
            "\nNo cross-feed correlations detected."
        )


# ============================================================
# DATABASE SUMMARY
# ============================================================

def show_database_summary():

    connection = sqlite3.connect(
        DATABASE_FILE
    )

    cursor = connection.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM iocs"
    )

    total = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM iocs
        WHERE ioc_type = 'ip'
    """)

    ip_count = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM iocs
        WHERE ioc_type = 'domain'
    """)

    domain_count = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM iocs
        WHERE ioc_type = 'url'
    """)

    url_count = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM iocs
        WHERE ioc_type = 'hash'
    """)

    hash_count = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM iocs
        WHERE risk_level = 'HIGH'
    """)

    high_count = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM iocs
        WHERE risk_level = 'MEDIUM'
    """)

    medium_count = cursor.fetchone()[0]

    connection.close()

    print("\n" + "=" * 65)
    print("DATABASE SUMMARY")
    print("=" * 65)

    print(
        f"Total Stored IOCs : {total}"
    )

    print(
        f"IP Addresses      : {ip_count}"
    )

    print(
        f"Domains           : {domain_count}"
    )

    print(
        f"URLs              : {url_count}"
    )

    print(
        f"Hashes            : {hash_count}"
    )

    print(
        f"High Risk IOCs    : {high_count}"
    )

    print(
        f"Medium Risk IOCs  : {medium_count}"
    )


# ============================================================
# SECURITY REPORT
# ============================================================

def generate_report(
    iocs,
    new_iocs,
    known_iocs
):

    report_file = os.path.join(
        REPORTS_DIR,
        "threat_report.txt"
    )

    total = sum(
        len(values)
        for values in iocs.values()
    )

    new_total = sum(
        len(values)
        for values in new_iocs.values()
    )

    known_total = sum(
        len(values)
        for values in known_iocs.values()
    )

    with open(
        report_file,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            "=" * 65 + "\n"
        )

        file.write(
            "THREAT INTELLIGENCE SECURITY REPORT\n"
        )

        file.write(
            "=" * 65 + "\n\n"
        )

        file.write(
            "Generated: "
            + datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            + "\n\n"
        )

        file.write(
            "IOC SUMMARY\n"
        )

        file.write(
            "-" * 65 + "\n"
        )

        file.write(
            f"Total Valid Unique IOCs: {total}\n"
        )

        file.write(
            f"IP Addresses: {len(iocs['ip'])}\n"
        )

        file.write(
            f"Domains: {len(iocs['domain'])}\n"
        )

        file.write(
            f"URLs: {len(iocs['url'])}\n"
        )

        file.write(
            f"Hashes: {len(iocs['hash'])}\n\n"
        )

        file.write(
            "IOC HISTORY\n"
        )

        file.write(
            "-" * 65 + "\n"
        )

        file.write(
            f"New IOCs: {new_total}\n"
        )

        file.write(
            f"Previously Known IOCs: {known_total}\n\n"
        )

        file.write(
            "NEW IOCs\n"
        )

        file.write(
            "-" * 65 + "\n"
        )

        for ioc_type, values in new_iocs.items():

            for indicator in values:

                file.write(
                    f"{indicator} | "
                    f"Type: {ioc_type} | "
                    f"Status: NEW\n"
                )

        if new_total == 0:

            file.write(
                "No new IOCs detected.\n"
            )

        file.write("\n")

        file.write(
            "INDICATORS\n"
        )

        file.write(
            "-" * 65 + "\n"
        )

        for ioc_type, values in iocs.items():

            file.write(
                f"\n[{ioc_type.upper()}]\n"
            )

            for indicator in values:

                risk = get_risk_level(
                    ioc_type
                )

                file.write(
                    f"{indicator} | Risk: {risk}\n"
                )

    print(
        f"\nSecurity report saved: {report_file}"
    )


# ============================================================
# BLOCKLIST GENERATION
# ============================================================

def generate_blocklist(iocs):

    # ----------------------------
    # Combined blocklist
    # ----------------------------

    blocklist_file = os.path.join(
        OUTPUT_DIR,
        "blocklist.txt"
    )

    with open(
        blocklist_file,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            "# THREAT INTELLIGENCE BLOCKLIST\n"
        )

        file.write(
            "# Generated: "
            + datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            + "\n\n"
        )

        for ioc_type, values in iocs.items():

            file.write(
                f"# {ioc_type.upper()}\n"
            )

            for indicator in values:

                file.write(
                    indicator + "\n"
                )

            file.write("\n")

    # ----------------------------
    # IP blocklist
    # ----------------------------

    ip_file = os.path.join(
        OUTPUT_DIR,
        "ip_blocklist.txt"
    )

    with open(
        ip_file,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            "# IP ADDRESS BLOCKLIST\n\n"
        )

        for ip in iocs["ip"]:

            file.write(
                ip + "\n"
            )

    # ----------------------------
    # Domain blocklist
    # ----------------------------

    domain_file = os.path.join(
        OUTPUT_DIR,
        "domain_blocklist.txt"
    )

    with open(
        domain_file,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            "# DOMAIN BLOCKLIST\n\n"
        )

        for domain in iocs["domain"]:

            file.write(
                domain + "\n"
            )

    # ----------------------------
    # URL blocklist
    # ----------------------------

    url_file = os.path.join(
        OUTPUT_DIR,
        "url_blocklist.txt"
    )

    with open(
        url_file,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            "# URL BLOCKLIST\n\n"
        )

        for url in iocs["url"]:

            file.write(
                url + "\n"
            )

    # ----------------------------
    # Hash blocklist
    # ----------------------------

    hash_file = os.path.join(
        OUTPUT_DIR,
        "hash_blocklist.txt"
    )

    with open(
        hash_file,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            "# FILE HASH BLOCKLIST\n\n"
        )

        for file_hash in iocs["hash"]:

            file.write(
                file_hash + "\n"
            )

    print(
        f"\nBlocklist saved: {blocklist_file}"
    )

    print(
        f"IP blocklist saved: {ip_file}"
    )

    print(
        f"Domain blocklist saved: {domain_file}"
    )

    print(
        f"URL blocklist saved: {url_file}"
    )

    print(
        f"Hash blocklist saved: {hash_file}"
    )


# ============================================================
# MAIN PROGRAM
# ============================================================

def main():

    show_banner()

    check_folders()

    setup_database()

    print(
        "\nReading threat intelligence feeds..."
    )

    feeds = read_feeds()

    if not feeds:

        print(
            "\nNo feed files found."
        )

        print(
            "Add .txt files inside the feeds folder."
        )

        return

    # --------------------------------------------------------
    # Collect all feed IOCs first
    # --------------------------------------------------------

    all_iocs = {
        "ip": [],
        "domain": [],
        "url": [],
        "hash": []
    }

    processed_feeds = []

    for feed in feeds:

        source = feed["source"]
        content = feed["content"]

        print(
            "\nProcessing:",
            source
        )

        print(
            "-" * 40
        )

        iocs = extract_iocs(
            content
        )

        print(
            f"IPs: {len(iocs['ip'])}"
        )

        print(
            f"Domains: {len(iocs['domain'])}"
        )

        print(
            f"URLs: {len(iocs['url'])}"
        )

        print(
            f"Hashes: {len(iocs['hash'])}"
        )

        processed_feeds.append({
            "source": source,
            "iocs": iocs
        })

        for ioc_type in all_iocs:

            all_iocs[ioc_type].extend(
                iocs[ioc_type]
            )

    # --------------------------------------------------------
    # Remove duplicates across feeds
    # --------------------------------------------------------

    for ioc_type in all_iocs:

        all_iocs[ioc_type] = sorted(
            set(all_iocs[ioc_type])
        )

    # --------------------------------------------------------
    # Detect new / previously known IOCs
    # BEFORE saving current run
    # --------------------------------------------------------

    new_iocs, known_iocs = detect_ioc_history(
        all_iocs
    )

    display_ioc_history(
        new_iocs,
        known_iocs
    )

    # --------------------------------------------------------
    # Save each feed to database
    # --------------------------------------------------------

    for feed in processed_feeds:

        save_iocs_to_database(
            feed["iocs"],
            feed["source"]
        )

        print(
            f"Saved validated IOCs from "
            f"{feed['source']} to database."
        )

    # --------------------------------------------------------
    # Display extracted IOCs
    # --------------------------------------------------------

    display_iocs(
        all_iocs
    )

    # --------------------------------------------------------
    # CSV
    # --------------------------------------------------------

    save_iocs_to_csv(
        all_iocs
    )

    # --------------------------------------------------------
    # Risk classification
    # --------------------------------------------------------

    classify_iocs(
        all_iocs
    )

    # --------------------------------------------------------
    # Cross-feed correlation
    # --------------------------------------------------------

    correlate_iocs(
        all_iocs
    )

    # --------------------------------------------------------
    # Database summary
    # --------------------------------------------------------

    show_database_summary()

    # --------------------------------------------------------
    # Security report
    # --------------------------------------------------------

    generate_report(
        all_iocs,
        new_iocs,
        known_iocs
    )

    # --------------------------------------------------------
    # Blocklists
    # --------------------------------------------------------

    generate_blocklist(
        all_iocs
    )

    print(
        "\n" + "=" * 65
    )

    print(
        "Threat intelligence processing completed successfully."
    )

    print(
        "=" * 65
    )


# ============================================================
# PROGRAM START
# ============================================================

if __name__ == "__main__":

    main()