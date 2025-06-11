#!/bin/bash

# Advanced Web Application & Database Fingerprinting Tool
# Developed by Defcon_ke A precise instrument for digital defense in DevSecOps.


# Directory to store all scan outputs
LOG_BASE_DIR="$HOME/Desktop/" 
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
TARGET="" # Renamed from TARGET_IP to TARGET to better reflect URL/IP input
RESOLVED_IP=""
SCAN_DIR=""
REPORT_FILE=""

# Nmap Timing Template: -T4 for aggressive speed.
NMAP_TIMING="-T4"

# Common web ports to check initially. Detailed scan will hit all.
WEB_PORTS="80,443,8000,8080,8443,8888"

# --- Functions ---

create_gitignore() {
    GITIGNORE_PATH=".gitignore"
    # We're ignoring the dedicated defscan_audits directory
    if [ ! -f "$GITIGNORE_PATH" ] || ! grep -q "$(basename "$LOG_BASE_DIR")/" "$GITIGNORE_PATH"; then
        echo "# Ignore DefScan output directories" > "$GITIGNORE_PATH"
        echo "$(basename "$LOG_BASE_DIR")/" >> "$GITIGNORE_PATH"
        echo "Created .gitignore to ignore scan outputs." | tee -a "$REPORT_FILE"
    else
        echo ".gitignore already exists and ignores scan outputs." | tee -a "$REPORT_FILE"
    fi
}

resolve_target() {
    # If the target starts with http:// or https://, extract the hostname/IP
    if [[ "$TARGET" =~ ^https?:// ]]; then
        HOSTNAME=$(echo "$TARGET" | sed -E 's|^https?://([^/]+).*|\1|')
    else
        HOSTNAME="$TARGET"
    fi

    # Try to resolve hostname to IP
    RESOLVED_IP=$(dig +short "$HOSTNAME" | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}$')
    
    if [ -z "$RESOLVED_IP" ]; then
        echo "Error: Could not resolve target '$HOSTNAME' to an IP address." | tee -a "$REPORT_FILE"
        exit 1
    fi
    echo "Resolved '$HOSTNAME' to IP: $RESOLVED_IP" | tee -a "$REPORT_FILE"
}

setup_environment() {
    mkdir -p "$LOG_BASE_DIR"
    # Use resolved IP for directory name
    SCAN_DIR="${LOG_BASE_DIR}/scan_${TIMESTAMP}_$(echo "$RESOLVED_IP" | tr './:' '_')" 
    mkdir -p "$SCAN_DIR"
    REPORT_FILE="${SCAN_DIR}/defcon.txt"

    echo "--- DefScan Report ---" | tee "$REPORT_FILE"
    echo "Scan started at: $(date)" | tee -a "$REPORT_FILE"
    echo "Target(s): $TARGET (Resolved IP: $RESOLVED_IP)" | tee -a "$REPORT_FILE"
    echo "Output directory: $SCAN_DIR" | tee -a "$REPORT_FILE"
    echo "Nmap Timing: ${NMAP_TIMING}" | tee -a "$REPORT_FILE"
    echo "--------------------------" | tee -a "$REPORT_FILE"

    create_gitignore
}

run_detailed_scan() {
    echo "" | tee -a "$REPORT_FILE"
    echo "[*] Running Detailed Network Scan (All Ports, Service Versions, OS Detection)..." | tee -a "$REPORT_FILE"
    # -p- : Scans all 65535 ports
    # -sV : Attempts to determine service versions
    # -O  : Attempts to determine OS
    # --reason : Shows why Nmap determined a port to be in a certain state
    # -oA : Output in all formats (normal, XML, grepable)
    nmap ${NMAP_TIMING} -p- -sV -O --reason -oA "${SCAN_DIR}/detailed_network_scan" "$RESOLVED_IP" | tee -a "$REPORT_FILE"
    echo "Detailed network scan complete." | tee -a "$REPORT_FILE"
}

run_web_app_scan() {
    echo "" | tee -a "$REPORT_FILE"
    echo "[*] Identifying Web Technologies and Common Web Vulnerabilities..." | tee -a "$REPORT_FILE"
    
    # Extract all open HTTP/S ports from the detailed network scan XML
    # This ensures we only run web scripts on relevant ports.
    WEB_SERVICES_FOUND=$(grep -oP 'portid="\K\d+" protocol="(tcp|udp)" state="open" service="(http|https)"' "${SCAN_DIR}/detailed_network_scan.xml" | cut -d'"' -f1 | sort -u | paste -sd,)
    
    if [ -z "$WEB_SERVICES_FOUND" ]; then
        echo "    No HTTP/HTTPS services found to run web-specific scans." | tee -a "$REPORT_FILE"
        return
    fi

    echo "    Running web-focused NSE scripts on ports: ${WEB_SERVICES_FOUND}" | tee -a "$REPORT_FILE"
    
    # Targeted web scan using a powerful suite of NSE scripts
    # http-enum: Detects web apps (WordPress, Joomla, etc.), common directories.
    # http-methods: Checks allowed HTTP methods (e.g., PUT, DELETE).
    # http-title: Gets the title of web pages.
    # http-auth-finder: Finds basic/digest auth forms.
    # http-vuln-cve2017-5638 (Struts RCE), http-vuln-cve2014-3704 (Drupal SQLi), etc.
    #   Using a broader --script http-vuln-* for more comprehensive checks.
    # http-robots.txt: Checks for disallowed paths.
    # ssl-enum-ciphers: Enumerates SSL/TLS ciphers and versions.
    # http-headers: Reveals HTTP response headers.
    # --script vuln : Catches a broad range of general vulnerabilities, including some web-related.
    
    nmap ${NMAP_TIMING} -p"${WEB_SERVICES_FOUND}" \
        --script "http-enum,http-methods,http-title,http-auth-finder,http-robots.txt,ssl-enum-ciphers,http-headers,http-waf-detect,http-vuln-*,vuln" \
        -oA "${SCAN_DIR}/web_app_scan" "$RESOLVED_IP" | tee -a "$REPORT_FILE" # Use RESOLVED_IP
    
    echo "Web application scan complete." | tee -a "$REPORT_FILE"
}

summarize_results() {
    echo "" | tee -a "$REPORT_FILE"
    echo "--- DefScan Summary ---" | tee -a "$REPORT_FILE" # Renamed Summary Header

    # Iterate through each host found in the detailed scan XML for comprehensive reporting
    # Use RESOLVED_IP for the grep for single target scans
    grep -oP 'host starttime="\K[^"]+"[^>]*>.*?<address addr="([^"]+)"' "${SCAN_DIR}/detailed_network_scan.xml" | while read -r line; do
        HOST_IP=$(echo "$line" | grep -oP 'addr="\K[^"]+')
        
        echo "" | tee -a "$REPORT_FILE"
        echo "### Host: $HOST_IP ###" | tee -a "$REPORT_FILE"

        # --- Open Ports & Services ---
        echo "  [*] Open Ports & Identified Services:" | tee -a "$REPORT_FILE"
        HOST_PORTS_DETAILS=$(grep -A 20 "<address addr=\"$HOST_IP\"" "${SCAN_DIR}/detailed_network_scan.xml" | grep -oP 'portid="\K\d+" state="open"[^>]*>.*?service name="([^"]+)" product="([^"]+)" version="([^"]+)"' | while read -r port_line; do
            PORT=$(echo "$port_line" | grep -oP 'portid="\K\d+')
            SERVICE=$(echo "$port_line" | grep -oP 'service name="\K[^"]+')
            PRODUCT=$(echo "$port_line" | grep -oP 'product="\K[^"]+')
            VERSION=$(echo "$port_line" | grep -oP 'version="\K[^"]+')
            if [ -z "$PRODUCT" ]; then PRODUCT="N/A"; fi # Handle cases where product is not found
            if [ -z "$VERSION" ]; then VERSION="N/A"; fi # Handle cases where version is not found
            echo "    - Port ${PORT} (${SERVICE}): Product: ${PRODUCT} Version: ${VERSION}"
        done)

        if [ -z "$HOST_PORTS_DETAILS" ]; then
            echo "    (No open ports with detailed service info.)" | tee -a "$REPORT_FILE"
        else
            echo "$HOST_PORTS_DETAILS" | tee -a "$REPORT_FILE"
        fi
        echo "" | tee -a "$REPORT_FILE"

        # --- Identified Web technologies ---
        echo "  [!!!] Identified Web Technologies & CMS:" | tee -a "$REPORT_FILE"
        WEB_TECH_FOUND=false

        # Look for CMS/Web App detections from http-enum script output for this host
        grep -A 50 "Host: $HOST_IP" "${SCAN_DIR}/web_app_scan.nmap" | grep -E "http-enum:|http-title:|http-fingerprints:" | while read -r line; do
            if echo "$line" | grep -q "http-enum: /wp-login.php (WordPress login utility)"; then
                echo "    - CMS: WordPress detected. (Login page found)" | tee -a "$REPORT_FILE"
                echo "      Potential Vulnerability: Outdated WordPress core, themes, or plugins. Brute-force attacks." | tee -a "$REPORT_FILE"
                echo "      Mitigation: Keep WP core/themes/plugins updated. Use strong passwords & 2FA. Implement login rate limiting/WAF." | tee -a "$REPORT_FILE"
                WEB_TECH_FOUND=true
            elif echo "$line" | grep -q "http-enum: /administrator/index.php (Joomla! login utility)"; then
                echo "    - CMS: Joomla! detected. (Admin login found)" | tee -a "$REPORT_FILE"
                echo "      Potential Vulnerability: Outdated Joomla! core, extensions. Default credentials. Brute-force attacks." | tee -a "$REPORT_FILE"
                echo "      Mitigation: Keep Joomla! core/extensions updated. Use strong passwords & 2FA. Monitor access logs." | tee -a "$REPORT_FILE"
                WEB_TECH_FOUND=true
            elif echo "$line" | grep -q "http-enum: /user (Drupal login utility)"; then
                echo "    - CMS: Drupal detected. (Login utility found)" | tee -a "$REPORT_FILE"
                echo "      Potential Vulnerability: Outdated Drupal core, modules. Default credentials." | tee -a "$REPORT_FILE"
                echo "      Mitigation: Keep Drupal core/modules updated. Implement strong passwords & 2FA. Regularly review security advisories." | tee -a "$REPORT_FILE"
                WEB_TECH_FOUND=true
            elif echo "$line" | grep -q "http-enum: /phpmyadmin/ (phpMyAdmin login utility)"; then
                echo "    - Web App: phpMyAdmin detected. (Database management interface)" | tee -a "$REPORT_FILE"
                echo "      Potential Vulnerability: Exposed phpMyAdmin. Default credentials. Brute-force." | tee -a "$REPORT_FILE"
                echo "      Mitigation: Restrict access to trusted IPs. Use strong, unique credentials. Consider removing if not essential from public access." | tee -a "$REPORT_FILE"
                WEB_TECH_FOUND=true
            elif echo "$line" | grep -q "http-enum: /admin/ (Common admin directory)"; then
                echo "    - Common Admin Directory '/admin/' detected." | tee -a "$REPORT_FILE"
                echo "      Potential Vulnerability: Exposed administrative interface. Brute-force attacks." | tee -a "$REPORT_FILE"
                echo "      Mitigation: Restrict access to trusted IPs. Use strong authentication and 2FA. Ensure no default credentials." | tee -a "$REPORT_FILE"
                WEB_TECH_FOUND=true
            elif echo "$line" | grep -q "http-title:"; then
                TITLE=$(echo "$line" | sed 's/.*http-title:\s*//')
                echo "    - Webpage Title: \"$TITLE\"" | tee -a "$REPORT_FILE"
                WEB_TECH_FOUND=true
            fi
        done

        # Look for general web server info from detailed scan
        if grep -q "80/tcp.*open.*http" "${SCAN_DIR}/detailed_network_scan.nmap" || grep -q "443/tcp.*open.*ssl/http" "${SCAN_DIR}/detailed_network_scan.nmap"; then
            WEB_SERVER_INFO=$(grep -A 20 "Host: $HOST_IP" "${SCAN_DIR}/detailed_network_scan.nmap" | grep -E "80/tcp|443/tcp" | grep "http" | head -n 1)
            if [ -n "$WEB_SERVER_INFO" ]; then
                echo "    - Web Server: $(echo "$WEB_SERVER_INFO" | awk '{print $NF}' | sed 's/(.*)//')" | tee -a "$REPORT_FILE"
                WEB_TECH_FOUND=true
            fi
        fi

        if [ "$WEB_TECH_FOUND" = false ]; then
            echo "    (No specific web technologies/CMS identified beyond basic HTTP service.)" | tee -a "$REPORT_FILE"
        fi
        echo "" | tee -a "$REPORT_FILE"

        # --- Identified Database Services (Mr. Robot Shit - ALL databases) ---
        echo "  [!!!] Identified Database Services:" | tee -a "$REPORT_FILE"
        DB_FOUND=false

        # MySQL/MariaDB
        if grep -q "3306/tcp.*open.*mysql" "${SCAN_DIR}/detailed_network_scan.nmap"; then
            MYSQL_VERSION=$(grep -A 20 "Host: $HOST_IP" "${SCAN_DIR}/detailed_network_scan.nmap" | grep "3306/tcp" | grep -oP 'MySQL\s+\K[^)]+')
            echo "    - Database: MySQL/MariaDB detected (Port 3306)" | tee -a "$REPORT_FILE"
            echo "      Version: ${MYSQL_VERSION:-N/A}" | tee -a "$REPORT_FILE"
            echo "      Potential Vulnerability: Weak/default credentials, unpatched vulnerabilities in specific versions, SQL Injection from web apps." | tee -a "$REPORT_FILE"
            echo "      Mitigation: Use strong, unique passwords. Restrict remote access to database. Apply security patches. Enforce least privilege. Implement input validation/prepared statements for web apps." | tee -a "$REPORT_FILE"
            DB_FOUND=true
        fi

        # PostgreSQL
        if grep -q "5432/tcp.*open.*postgresql" "${SCAN_DIR}/detailed_network_scan.nmap"; then
            PGSQL_VERSION=$(grep -A 20 "Host: $HOST_IP" "${SCAN_DIR}/detailed_network_scan.nmap" | grep "5432/tcp" | grep -oP 'PostgreSQL\s+\K[^)]+')
            echo "    - Database: PostgreSQL detected (Port 5432)" | tee -a "$REPORT_FILE"
            echo "      Version: ${PGSQL_VERSION:-N/A}" | tee -a "$REPORT_FILE"
            echo "      Potential Vulnerability: Weak/default credentials, unpatched vulnerabilities, insecure pg_hba.conf." | tee -a "$REPORT_FILE"
            echo "      Mitigation: Use strong, unique passwords. Restrict remote access. Apply security patches. Configure host-based authentication (pg_hba.conf)." | tee -a "$REPORT_FILE"
            DB_FOUND=true
        fi
        
        # MS SQL
        if grep -q "1433/tcp.*open.*ms-sql-s" "${SCAN_DIR}/detailed_network_scan.nmap"; then
            MSSQL_VERSION=$(grep -A 20 "Host: $HOST_IP" "${SCAN_DIR}/detailed_network_scan.nmap" | grep "1433/tcp" | grep -oP 'product:\s+Microsoft SQL Server\s+\K[^,]+')
            echo "    - Database: Microsoft SQL Server detected (Port 1433)" | tee -a "$REPORT_FILE"
            echo "      Version: ${MSSQL_VERSION:-N/A}" | tee -a "$REPORT_FILE"
            echo "      Potential Vulnerability: Weak/default SA credentials, SQL injection, unpatched vulnerabilities." | tee -a "$REPORT_FILE"
            echo "      Mitigation: Strong SA password. Disable mixed mode if not needed. Apply security updates. Implement least privilege access." | tee -a "$REPORT_FILE"
            DB_FOUND=true
        fi

        # MongoDB
        if grep -q "27017/tcp.*open.*mongodb" "${SCAN_DIR}/detailed_network_scan.nmap"; then
            MONGODB_VERSION=$(grep -A 20 "Host: $HOST_IP" "${SCAN_DIR}/detailed_network_scan.nmap" | grep "27017/tcp" | grep -oP 'MongoDB\s+MongoDB\s+\K[^)]+')
            echo "    - Database: MongoDB detected (Port 27017)" | tee -a "$REPORT_FILE"
            echo "      Version: ${MONGODB_VERSION:-N/A}" | tee -a "$REPORT_FILE"
            echo "      Potential Vulnerability: No authentication, exposed to public internet, unpatched versions." | tee -a "$REPORT_FILE"
            echo "      Mitigation: Enable authentication (SCRAM-SHA-1/256). Bind to specific IP addresses. Implement firewalls. Encrypt sensitive data." | tee -a "$REPORT_FILE"
            DB_FOUND=true
        fi

        # Redis
        if grep -q "6379/tcp.*open.*redis" "${SCAN_DIR}/detailed_network_scan.nmap"; then
            REDIS_VERSION=$(grep -A 20 "Host: $HOST_IP" "${SCAN_DIR}/detailed_network_scan.nmap" | grep "6379/tcp" | grep -oP 'Redis\s+key-value\s+store\s+\K[^)]+')
            echo "    - Database: Redis detected (Port 6379)" | tee -a "$REPORT_FILE"
            echo "      Version: ${REDIS_VERSION:-N/A}" | tee -a "$REPORT_FILE"
            echo "      Potential Vulnerability: No authentication, exposed to public internet, command injection." | tee -a "$REPORT_FILE"
            echo "      Mitigation: Enable authentication (requirepass). Bind to specific IP addresses. Implement firewalls. Rename dangerous commands." | tee -a "$REPORT_FILE"
            DB_FOUND=true
        fi

        # Oracle (standard port)
        if grep -q "1521/tcp.*open.*oracle" "${SCAN_DIR}/detailed_network_scan.nmap"; then
            ORACLE_SERVICE=$(grep -A 20 "Host: $HOST_IP" "${SCAN_DIR}/detailed_network_scan.nmap" | grep "1521/tcp" | grep -oP 'service name:\s+\K[^)]+')
            echo "    - Database: Oracle detected (Port 1521)" | tee -a "$REPORT_FILE"
            echo "      Service: ${ORACLE_SERVICE:-N/A}" | tee -a "$REPORT_FILE"
            echo "      Potential Vulnerability: Weak/default credentials, unpatched vulnerabilities, TNS Listener vulnerabilities." | tee -a "$REPORT_FILE"
            echo "      Mitigation: Use strong, unique credentials. Apply latest security patches. Secure TNS Listener. Restrict network access." | tee -a "$REPORT_FILE"
            DB_FOUND=true
        fi

        # Cassandra (standard port)
        if grep -q "9042/tcp.*open.*cassandra" "${SCAN_DIR}/detailed_network_scan.nmap"; then
            CASSANDRA_VERSION=$(grep -A 20 "Host: $HOST_IP" "${SCAN_DIR}/detailed_network_scan.nmap" | grep "9042/tcp" | grep -oP 'Cassandra\s+\K[^)]+')
            echo "    - Database: Cassandra detected (Port 9042)" | tee -a "$REPORT_FILE"
            echo "      Version: ${CASSANDRA_VERSION:-N/A}" | tee -a "$REPORT_FILE"
            echo "      Potential Vulnerability: Weak/default credentials, exposed JMX, unpatched vulnerabilities." | tee -a "$REPORT_FILE"
            echo "      Mitigation: Enable authentication/authorization. Restrict JMX access. Apply security updates. Implement node-to-node encryption." | tee -a "$REPORT_FILE"
            DB_FOUND=true
        fi

        # Add more database checks here as needed
        # Example: ElasticSearch (9200/9300), CouchDB (5984), etc.
        # if grep -q "9200/tcp.*open.*elasticsearch" "${SCAN_DIR}/detailed_network_scan.nmap"; then
        #     echo "    - Database: ElasticSearch detected (Port 9200)" | tee -a "$REPORT_FILE"
        #     echo "      Potential Vulnerability: Unauthenticated access, exposed to public internet." | tee -a "$REPORT_FILE"
        #     echo "      Mitigation: Enable X-Pack Security (authentication/authorization). Bind to specific IP addresses. Implement firewalls." | tee -a "$REPORT_FILE"
        #     DB_FOUND=true
        # fi

        if [ "$DB_FOUND" = false ]; then
            echo "    (No common database services identified on standard ports.)" | tee -a "$REPORT_FILE"
        fi
        echo "" | tee -a "$REPORT_FILE"

        # --- Firewall/Filtering Hints ---
        echo "  --- Firewall/Filtering Hints ---" | tee -a "$REPORT_FILE"
        HOST_FIREWALL_HINTS=$(grep -A 50 "Host: $HOST_IP" "${SCAN_DIR}/detailed_network_scan.nmap" | grep "reason: filtered")
        if [ -n "$HOST_FIREWALL_HINTS" ]; then
            echo "    [!] Some ports are reported as 'filtered', suggesting a firewall or packet filtering is present." | tee -a "$REPORT_FILE"
            echo "        Review scan logs for details on specific filtered ports." | tee -a "$REPORT_FILE"
        else
            echo "    [*] No 'filtered' ports explicitly found for this host, but this doesn't guarantee no firewall." | tee -a "$REPORT_FILE"
        fi
        echo "" | tee -a "$REPORT_FILE"

    done # End of host iteration
    
    echo "Full Nmap outputs are located in: $SCAN_DIR" | tee -a "$REPORT_FILE"
    echo "Scan summary complete. Report saved to $REPORT_FILE" | tee -a "$REPORT_FILE"
}

# --- Main Execution ---
if [ -z "$1" ]; then
    echo "Usage: $0 <target_ip_or_range_or_url>"
    echo "Example: $0 192.168.1.1"
    echo "Example: $0 10.10.237.0/24"
    echo "Example: $0 example.com"
    echo "Example: $0 https://www.target-website.com"
    exit 1
fi

TARGET="$1" # Now accepts URL or IP

# Basic check for Nmap and dig
if ! command -v nmap &> /dev/null; then
    echo "Error: Nmap is not installed. Please install Nmap to run this script."
    exit 1
fi
if ! command -v dig &> /dev/null; then
    echo "Error: 'dig' command not found. Please install 'dnsutils' (e.g., 'sudo apt install dnsutils') to run this script."
    exit 1
fi


resolve_target # Resolve target to IP
setup_environment
run_detailed_scan
run_web_app_scan # Run specific web app scan after detailed scan

summarize_results

echo "--- All scans finished Use everything wisely ---" | tee -a "$REPORT_FILE"
