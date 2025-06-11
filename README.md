DefScan
Automated Web & Database Security Reconnaissance Tool
DefScan is a formidable Bash script designed to empower SOC 1 analysts and developers with rapid, actionable insights into the security posture of web applications and their underlying database infrastructures. This tool significantly streamlines the "shift-left" security process within DevSecOps by automating comprehensive reconnaissance, pinpointing critical vulnerabilities, and providing immediate, tailored mitigation strategies. It's built to be a proactive force in safeguarding digital assets against the evolving threat landscape of 2025.

✨ Features
Intelligent Target Resolution: Accepts both IP addresses and full URLs (http://, https://) as targets, automatically resolving hostnames to IP addresses for precise scanning.

Comprehensive Network & Web Scanning:

All-Port Network Scan: Conducts a full port scan (0-65535) to identify all exposed services.

Service & OS Fingerprinting: Accurately identifies running services, their versions, and the underlying operating system.

Advanced Web Application Analysis: Leverages a curated suite of Nmap Scripting Engine (NSE) scripts to detect common web server misconfigurations, dangerous files, and well-known web application vulnerabilities.

Deep Web Technology Identification: Automatically identifies popular Content Management Systems (CMS) like WordPress, Joomla!, and Drupal, along with common web applications like phpMyAdmin, providing specific insights and potential vulnerabilities.

Extensive Database Service Fingerprinting: Goes beyond the basics to detect and report on a wide array of database technologies, including:

Relational: MySQL/MariaDB, PostgreSQL, Microsoft SQL Server, Oracle.

NoSQL: MongoDB, Redis, Cassandra.

For each detected database, it provides version information, potential vulnerabilities, and immediate mitigation steps.

Actionable Mitigation Guidance: The tool's core strength lies in its ability to not just identify vulnerabilities, but to provide clear, concise, and direct mitigation techniques for each finding. This enables developers to rapidly address security flaws.

Firewall & Filtering Hints: Uses Nmap's --reason flag to infer the presence and behavior of network firewalls or packet filtering devices.

Streamlined Reporting: Generates a clean, timestamped defcon.txt report summarizing all findings, their potential impact, and crucial remediation advice, organized for quick developer consumption.

🚀 Getting Started
To wield the power of DefScan, ensure you have Nmap and dig (part of dnsutils) installed on your system.

Prerequisites:

Nmap: The primary scanning engine.

Debian/Ubuntu: sudo apt update && sudo apt install nmap

Arch Linux: sudo pacman -S nmap

Fedora/RHEL: sudo dnf install nmap

macOS (with Homebrew): brew install nmap

dig: Used for resolving hostnames to IP addresses.

Debian/Ubuntu: sudo apt update && sudo apt install dnsutils

Fedora/RHEL: sudo dnf install bind-utils

macOS (built-in): Usually comes pre-installed.

Bash: The script runs on Bash (standard on most Linux/macOS systems).

Installation:

Clone the repository: Navigate to your desired location (e.g., ~/Desktop/GITHUB/) and clone the DefScan repository.

git clone https://github.com/Bakhuya/DefScan.git # REPLACE with YOUR actual repo URL
cd DefScan

Make the script executable:

chmod +x defscan.sh

💡 Usage
Execute DefScan from your terminal, providing the target IP address, IP range (CIDR), or URL as an argument.

./defscan.sh <target_ip_or_range_or_url>

Examples:

Scan a single IP address:

./defscan.sh 192.168.1.1

Scan an entire subnet (CIDR):

./defscan.sh 10.10.237.0/24

Scan a domain name:

./defscan.sh example.com

Scan a full URL:

./defscan.sh https://www.target-website.com

Output Location:

All scan results, including the detailed defcon.txt summary report and raw Nmap outputs (XML, grepable, normal), will be stored in a unique, timestamped directory under the configured LOG_BASE_DIR (default: ~/Desktop/)

⚙️ Configuration (optional)

LOG_BASE_DIR: Adjust the base directory where all scan output folders are created.

NMAP_TIMING: Modify Nmap's scan timing template (default: -T4 for aggressive speed). For stealthier operations, consider -T2 (Polite), or for maximum aggression -T5 (Insane), but be mindful of network stability.

📊 Output Example (defcon.txt snippet)
--- DefScan Report ---
Scan started at: Wed Jun 11 05:08:30 PM EAT 2025
Target(s): https://target.com/ (Resolved IP: 103.23.52.109)
Output directory: /Desktop/GITHUB/defscan/
Nmap Timing: -T4
--------------------------
.gitignore already exists and ignores scan outputs.

[*] Running Detailed Network Scan (All Ports, Service Versions, OS Detection)...
... (Nmap output for detailed scan) ...
Detailed network scan complete.

[*] Identifying Web Technologies and Common Web Vulnerabilities...
    Running web-focused NSE scripts on ports: 80,443

... (Nmap output for web app scan) ...
Web application scan complete.

--- DefScan Summary ---

### Host: 103.23.52.109 ###
  [*] Open Ports & Identified Services:
    - Port 80 (http): Product: nginx Version: N/A
    - Port 443 (https): Product: nginx Version: N/A

  [!!!] Identified Web Technologies & CMS:
    - Web Server: nginx
    - Webpage Title: "example.com - Find Your Next Opportunity"
    (No specific web technologies/CMS identified beyond basic HTTP service.)

  [!!!] Identified Database Services:
    (No common database services identified on standard ports.)

  --- Firewall/Filtering Hints ---
    [*] No 'filtered' ports explicitly found for this host, but this doesn't guarantee no firewall.

Full Nmap outputs are located in: /Desktop/defscan
Scan summary complete. Report saved to /Desktop/defcon.txt
--- All scans finished ---

📈 Future Enhancements (Ideas for Expansion)
Deeper Vulnerability Mapping: Integrate with external APIs (e.g., CVE Details, Exploit-DB, Vulners.com) to automatically fetch and display detailed CVE information and exploits for identified versions.

HTML/PDF Reporting: Develop robust report generation in more presentable formats.

Notification Integration: Add options for sending scan completion alerts and critical findings via email, Slack, or other communication platforms.

Advanced Evasion Techniques: Implement more sophisticated Nmap stealth options (e.g., --scan-delay, --max-rate, custom packet flags).

Dynamic Wordlist Integration: Allow users to specify custom wordlists for directory brute-forcing (integrating tools like gobuster or dirb if needed).

Dockerization: Provide a Dockerfile to encapsulate the tool for easy deployment across various environments.

CI/CD Pipeline Hooks: Develop basic integration points for automated execution within CI/CD pipelines.

🤝 Contributing
Contributions are highly valued! If you have suggestions for improvements, feature requests, or encounter any bugs, please feel free to open an issue or submit a pull request on the GitHub repository.

📄 License
 See the LICENSE file in the repository for full details.

📧 Contact
For any inquiries or collaboration opportunities, connect with me:

GitHub: @Bakhuya 
