import re

TAGS_STRIP      = ["script", "style", "noscript", "nav", "footer"]
NVD_METRIC_KEYS = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
RE_CVE          = re.compile(r'CVE-[0-9]{4}-[0-9]+', re.I)
RE_CVSS         = re.compile(r'(?:CVSS|impatto sistemico)[\s:a-zA-Z]*([0-9]{1,2}\.[0-9]+)', re.I)
RE_TECH         = re.compile(r'(?:in|per|relativa a)\s([A-Z][a-zA-Z0-9_-]+)')
RE_ARGOMENTI    = re.compile(r"Argomenti", re.I)
RE_KEV          = re.compile(r'\bkev\b', re.I)
RE_POC          = re.compile(r'\bpoc\b', re.I)

REGOLE: list[tuple[str, re.Pattern]] = [
    ("Ransomware",                    re.compile(r"ransomware|cryptolocker|lockbit|blackbasta", re.I)),
    ("Zero-Day Exploit",              re.compile(r"zero-day|0-day|zeroday", re.I)),
    ("RCE (Remote Code Execution)",   re.compile(r"\brce\b|esecuzione remota|remote code execution|esecuzione di codice", re.I)),
    ("Privilege Escalation",          re.compile(r"privilege escalation|escalation dei privilegi|\beop\b|elevazione dei privilegi", re.I)),
    ("SQL Injection (SQLi)",          re.compile(r"sql injection|\bsqli\b|injection sql", re.I)),
    ("Cross-Site Scripting (XSS)",    re.compile(r"cross-site scripting|\bxss\b", re.I)),
    ("Authentication Bypass",         re.compile(r"authentication bypass|bypass dell'autenticazione|aggiramento dell'autenticazione", re.I)),
    ("Directory Traversal",           re.compile(r"directory traversal|path traversal|\blfi\b|local file inclusion", re.I)),
    ("Denial of Service (DoS/DDoS)",  re.compile(r"\bddos\b|\bdos\b|denial of service|negazione di servizio", re.I)),
    ("Phishing / Social Engineering", re.compile(r"phishing|smishing|vishing|ingegneria sociale|esca", re.I)),
    ("Malware / Infostealer",         re.compile(r"malware|stealer|trojan|botnet|spyware|backdoor|webshell|keylogger", re.I)),
    ("Information Disclosure",        re.compile(r"information disclosure|data leak|esposizione di informazioni|fuga di dati", re.I)),
    ("Spoofing",                      re.compile(r"spoofing|falsificazione", re.I)),
]

TECH_KEYWORDS: list[tuple[str, str]] = [
    # Microsoft
    ("windows server",          "Windows Server"),
    ("windows",                 "Windows"),
    ("microsoft office",        "Microsoft Office"),
    ("sharepoint",              "SharePoint"),
    ("exchange server",         "Exchange Server"),
    ("azure",                   "Azure"),
    ("microsoft",               "Microsoft"),
    # Google
    ("google chrome",           "Google Chrome"),
    ("android",                 "Android"),
    ("google",                  "Google"),
    # Apple
    ("macos",                   "macOS"),
    ("ios",                     "iOS"),
    ("safari",                  "Safari"),
    ("apple",                   "Apple"),
    # Linux / OS
    ("linux kernel",            "Linux Kernel"),
    ("ubuntu",                  "Ubuntu"),
    ("debian",                  "Debian"),
    ("red hat",                 "Red Hat"),
    ("centos",                  "CentOS"),
    # Web server / infra
    ("apache tomcat",           "Apache Tomcat"),
    ("apache http",             "Apache HTTP Server"),
    ("apache",                  "Apache"),
    ("nginx",                   "Nginx"),
    ("ingress-nginx",           "Ingress-NGINX"),
    ("iis",                     "IIS"),
    # Networking / Security
    ("cisco ios",               "Cisco IOS"),
    ("cisco",                   "Cisco"),
    ("fortinet",                "Fortinet"),
    ("fortigate",               "FortiGate"),
    ("palo alto",               "Palo Alto"),
    ("juniper",                 "Juniper"),
    ("f5",                      "F5"),
    ("ivanti",                  "Ivanti"),
    ("sonicwall",               "SonicWall"),
    ("vmware",                  "VMware"),
    ("citrix",                  "Citrix"),
    ("aruba",                   "Aruba"),
    ("checkpoint",              "Check Point"),
    ("sophos",                  "Sophos"),
    ("symantec",                "Symantec"),
    ("crowdstrike",             "CrowdStrike"),
    ("tenable",                 "Tenable"),
    ("nessus",                  "Nessus"),
    # Dev / Framework / CMS
    ("gitlab",                  "GitLab"),
    ("github enterprise",       "GitHub Enterprise"),
    ("github",                  "GitHub"),
    ("jenkins",                 "Jenkins"),
    ("kubernetes",              "Kubernetes"),
    ("docker",                  "Docker"),
    ("spring framework",        "Spring Framework"),
    ("spring",                  "Spring Framework"),
    ("django",                  "Django"),
    ("wordpress",               "WordPress"),
    ("drupal",                  "Drupal"),
    ("joomla",                  "Joomla"),
    ("craft cms",               "Craft CMS"),
    ("craft",                   "Craft"),
    ("php",                     "PHP"),
    ("node.js",                 "Node.js"),
    ("ruby on rails",           "Ruby on Rails"),
    ("ruby",                    "Ruby"),
    ("nextcloud",               "Nextcloud"),
    # Database
    ("mysql",                   "MySQL"),
    ("postgresql",              "PostgreSQL"),
    ("mongodb",                 "MongoDB"),
    ("redis",                   "Redis"),
    ("oracle database",         "Oracle Database"),
    ("oracle",                  "Oracle"),
    ("mssql",                   "MSSQL"),
    ("sqlite",                  "SQLite"),
    # Browser / mail client
    ("mozilla firefox",         "Firefox"),
    ("firefox",                 "Firefox"),
    ("thunderbird",             "Thunderbird"),
    ("chromium",                "Chromium"),
    ("mozilla",                 "Mozilla"),
    # Crypto / SSL
    ("openssh",                 "OpenSSH"),
    ("openssl",                 "OpenSSL"),
    ("samba",                   "Samba"),
    ("freetype",                "FreeType"),
    # Backup / storage
    ("veeam",                   "Veeam"),
    ("backup exec",             "Backup Exec"),
    ("backup",                  "Backup"),
    # HPE
    ("hpe aruba",               "HPE Aruba"),
    ("hpe",                     "HPE"),
    # Altri vendor
    ("atlassian",               "Atlassian"),
    ("confluence",              "Confluence"),
    ("jira",                    "Jira"),
    ("adobe",                   "Adobe"),
    ("acrobat",                 "Adobe Acrobat"),
    ("coldfusion",              "ColdFusion"),
    ("sap",                     "SAP"),
    ("zimbra",                  "Zimbra"),
    ("moodle",                  "Moodle"),
    ("openfire",                "Openfire"),
    ("zabbix",                  "Zabbix"),
    ("grafana",                 "Grafana"),
    ("prometheus",              "Prometheus"),
    ("elastic",                 "Elasticsearch"),
    ("kibana",                  "Kibana"),
    ("splunk",                  "Splunk"),
]