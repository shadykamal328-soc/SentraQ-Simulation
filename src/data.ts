import type { AttackScenario, Severity } from "./types";

export const RULES: { rule: string; category: string; severity: Severity }[] = [
  { rule: "VPN login failed from known travel ASN", category: "Identity", severity: "low" },
  { rule: "Impossible travel for Microsoft 365 user", category: "Identity", severity: "medium" },
  { rule: "Endpoint malware heuristic: unsigned script", category: "Execution", severity: "medium" },
  { rule: "Suspicious PowerShell command line", category: "Execution", severity: "high" },
  { rule: "Outbound connection to low reputation IP", category: "Command and Control", severity: "medium" },
  { rule: "DNS request volume anomaly", category: "Network", severity: "low" },
  { rule: "Admin share access from workstation", category: "Lateral Movement", severity: "medium" },
  { rule: "EDR blocked credential dump attempt", category: "Credential Access", severity: "high" },
  { rule: "User opened macro-enabled Office document", category: "Initial Access", severity: "medium" },
  { rule: "Firewall denied unusual outbound port", category: "Network", severity: "low" },
  { rule: "Service account interactive login", category: "Identity", severity: "medium" },
  { rule: "Large file copy to temporary folder", category: "Collection", severity: "medium" },
  { rule: "Rare process spawned by Office", category: "Execution", severity: "high" },
  { rule: "Cloud API token used from new device", category: "Cloud", severity: "medium" },
  { rule: "Antivirus PUA detection", category: "Malware", severity: "low" },
  { rule: "Web proxy category mismatch", category: "Proxy", severity: "low" },
];

export const USERS = [
  "l1.analyst",
  "h.patel",
  "a.hassan",
  "m.garcia",
  "svc-backup",
  "svc-deploy",
  "finance.ap",
  "it.admin",
  "sales.ops",
  "hr.shared",
];

export const HOSTS = [
  "WS-FIN-014",
  "WS-HR-022",
  "WS-DEV-101",
  "SRV-DC01",
  "SRV-FILE02",
  "SRV-WEB03",
  "SRV-BACKUP01",
  "SRV-BUILD01",
  "CLOUD-M365",
  "EDR-MANAGER",
];

export const EXT_IPS = [
  "185.220.101.45",
  "194.165.16.77",
  "45.227.253.99",
  "103.224.182.251",
  "91.219.236.18",
  "5.188.86.114",
  "31.13.195.22",
];

export const ANALYST_THOUGHTS = [
  "This VPN alert looks noisy, but I need to validate it.",
  "If this is false positive again, I just lost another five minutes.",
  "Checking user history before I escalate.",
  "The queue is growing faster than I can triage.",
  "This one has benign indicators, but the timing is strange.",
  "I need EDR, identity, proxy, and firewall context together.",
  "Automation is moving faster than my manual checks.",
  "Too many medium alerts, not enough signal.",
  "I am still on the first alert and the feed is exploding.",
  "Something real could be hiding behind this noise.",
];

export const INVESTIGATION_STEPS = [
  "Opening alert context in SIEM.",
  "Checking user sign-in history and device compliance.",
  "Pivoting to EDR process tree.",
  "Looking up IP reputation and ASN history.",
  "Correlating proxy, DNS, and firewall events.",
  "Reviewing previous tickets for the same rule.",
  "Finding matching events across the last 24 hours.",
  "Waiting on enrichment results from threat intel.",
  "Comparing behavior with baseline for this user.",
  "Drafting initial disposition for L2 handoff.",
  "Conclusion: likely false positive, no escalation.",
];

export const ATTACK_SCENARIOS: AttackScenario[] = [
  {
    id: "phishing-ransomware",
    name: "Automated Phishing to Ransomware",
    shortName: "Phishing Chain",
    summary:
      "The L1 analyst spends the first minutes validating a noisy VPN alert while an automated phishing payload lands, steals credentials, moves laterally, and starts ransomware staging.",
    falsePositiveFocus:
      "VPN login failed from travel ASN for h.patel. Looks risky, but it is a known roaming user on a managed laptop.",
    attackerAutomation:
      "Phishing kit, macro loader, credential dumper, SMB scanner, and ransomware deploy script run with almost no human delay.",
    blastRadius: "Finance workstation, file server, domain controller, backups",
    entryNode: "WS-FIN-014",
    targetNode: "SRV-DC01",
    attackRules: [
      { rule: "Macro payload spawned encoded PowerShell", category: "Execution", severity: "high", phase: "execution" },
      { rule: "Beacon to command server over HTTPS", category: "Command and Control", severity: "high", phase: "initial" },
      { rule: "LSASS memory read by unsigned binary", category: "Credential Access", severity: "critical", phase: "execution" },
      { rule: "SMB lateral movement to file server", category: "Lateral Movement", severity: "high", phase: "lateral" },
      { rule: "Shadow copy deletion command observed", category: "Impact", severity: "critical", phase: "impact" },
    ],
    attackLogs: [
      { t: "T+00:00", source: "M365", message: "h.patel received invoice_Q2.xlsm from external sender; SPF pass, DMARC aligned", severity: "medium" },
      { t: "T+00:06", source: "EDR", message: "WINWORD.EXE spawned powershell.exe -nop -w hidden -enc JAB3AGM...", severity: "high" },
      { t: "T+00:10", source: "Proxy", message: "WS-FIN-014 connected to 185.220.101.45:443 /api/checkin", severity: "high" },
      { t: "T+00:16", source: "EDR", message: "rundll32.exe loaded unsigned module from AppData\\Roaming\\TeamsCache", severity: "high" },
      { t: "T+00:21", source: "Identity", message: "svc-backup token requested from WS-FIN-014 outside normal host pattern", severity: "critical" },
      { t: "T+00:27", source: "Network", message: "SMB session fan-out: WS-FIN-014 to 38 internal hosts in 12 seconds", severity: "high" },
      { t: "T+00:35", source: "Windows", message: "vssadmin delete shadows /all /quiet executed on SRV-FILE02", severity: "critical" },
      { t: "T+00:42", source: "EDR", message: "ransomdeploy.ps1 copied to ADMIN$ on multiple hosts", severity: "critical" },
    ],
    topology: {
      nodes: [
        { id: "internet", label: "Internet Edge", role: "external ingress", x: 8, y: 18, status: "suspicious" },
        { id: "mail", label: "Microsoft 365 EOP", role: "mail security gateway", x: 28, y: 18, status: "noisy" },
        { id: "ws", label: "FIN-WS-014", role: "finance endpoint", x: 48, y: 38, status: "compromised" },
        { id: "file", label: "File Services Cluster", role: "shared storage", x: 68, y: 30, status: "critical" },
        { id: "dc", label: "AD-DC01", role: "domain controller", x: 88, y: 50, status: "critical" },
        { id: "backup", label: "Backup Vault", role: "immutable backup store", x: 68, y: 70, status: "suspicious" },
        { id: "soc", label: "SOC / SIEM", role: "alert console", x: 28, y: 72, status: "noisy" },
      ],
      links: [
        { from: "internet", to: "mail", status: "attack" },
        { from: "mail", to: "ws", status: "attack" },
        { from: "ws", to: "file", status: "attack" },
        { from: "file", to: "dc", status: "attack" },
        { from: "file", to: "backup", status: "attack" },
        { from: "ws", to: "soc", status: "noisy" },
      ],
    },
    outcomeTitle: "Ransomware staging completed",
    outcome: [
      "The first alert was a false positive, but the manual investigation consumed the L1 analyst's attention.",
      "The automated attack chain moved from phishing to credential theft to lateral movement before the analyst finished triage.",
      "The critical alerts were present, but buried inside a high-volume queue with similar-looking medium alerts.",
    ],
  },
  {
    id: "credential-stuffing-cloud",
    name: "Credential Stuffing to Cloud Exfiltration",
    shortName: "Cloud Takeover",
    summary:
      "A password-spraying botnet creates thousands of low-confidence identity alerts while one successful login abuses OAuth consent and exports cloud data.",
    falsePositiveFocus:
      "Repeated failed MFA for sales.ops from a mobile carrier. Similar tickets closed as user travel and stale sessions.",
    attackerAutomation:
      "Botnet rotation, residential proxies, token replay, mailbox rules, and cloud storage export are chained automatically.",
    blastRadius: "M365, executive mailbox, customer export bucket",
    entryNode: "CLOUD-M365",
    targetNode: "Customer Data",
    attackRules: [
      { rule: "Password spray across tenant users", category: "Initial Access", severity: "medium", phase: "initial" },
      { rule: "Successful login after distributed failures", category: "Identity", severity: "high", phase: "initial" },
      { rule: "Suspicious OAuth consent granted", category: "Persistence", severity: "critical", phase: "persistence" },
      { rule: "Mailbox forwarding rule to external domain", category: "Collection", severity: "high", phase: "exfiltration" },
      { rule: "Bulk download from SharePoint library", category: "Exfiltration", severity: "critical", phase: "exfiltration" },
    ],
    attackLogs: [
      { t: "T+00:00", source: "Identity", message: "1,842 failed sign-ins across 96 users from rotating residential ASNs", severity: "medium" },
      { t: "T+00:08", source: "Entra ID", message: "sales.ops successful login from ASN previously seen in failed attempts", severity: "high" },
      { t: "T+00:13", source: "Cloud App", message: "OAuth app 'Q4 Revenue Sync' granted Mail.Read and Files.Read.All", severity: "critical" },
      { t: "T+00:19", source: "Exchange", message: "Inbox rule created: forward invoices and contracts to audit-sync-mail.com", severity: "high" },
      { t: "T+00:26", source: "SharePoint", message: "Bulk export started: /Customers/Enterprise/*.xlsx, 14.8 GB", severity: "critical" },
      { t: "T+00:34", source: "CASB", message: "Download velocity exceeded baseline by 920 percent", severity: "critical" },
    ],
    topology: {
      nodes: [
        { id: "botnet", label: "Spray Botnet", role: "rotating proxies", x: 8, y: 35, status: "suspicious" },
        { id: "idp", label: "Microsoft Entra ID", role: "identity provider", x: 30, y: 35, status: "noisy" },
        { id: "m365", label: "Microsoft 365 Tenant", role: "mail and files", x: 52, y: 35, status: "compromised" },
        { id: "oauth", label: "OAuth Consent App", role: "persistence", x: 72, y: 20, status: "critical" },
        { id: "data", label: "SharePoint Data", role: "customer content store", x: 88, y: 52, status: "critical" },
        { id: "soc", label: "SOC / CASB", role: "alert console", x: 32, y: 72, status: "noisy" },
      ],
      links: [
        { from: "botnet", to: "idp", status: "attack" },
        { from: "idp", to: "m365", status: "attack" },
        { from: "m365", to: "oauth", status: "attack" },
        { from: "oauth", to: "data", status: "attack" },
        { from: "m365", to: "soc", status: "noisy" },
      ],
    },
    outcomeTitle: "Cloud data export completed",
    outcome: [
      "Low-confidence identity alerts overwhelmed the first triage queue.",
      "The one successful login looked similar to the surrounding failed attempts.",
      "OAuth persistence let the attacker continue even after the password was reset.",
    ],
  },
  {
    id: "devops-supply-chain",
    name: "DevOps Token Abuse to Supply Chain Push",
    shortName: "DevOps Chain",
    summary:
      "A build token is stolen from a developer endpoint. While L1 investigates a noisy antivirus detection, the attacker modifies CI/CD artifacts and pushes a backdoored package.",
    falsePositiveFocus:
      "Antivirus PUA on WS-DEV-101 from a developer tool installer. Common noisy alert in engineering machines.",
    attackerAutomation:
      "Token scraper, repository scanner, CI workflow editor, package publisher, and cloud secret discovery run as a scripted chain.",
    blastRadius: "Build server, source repository, package registry, production service",
    entryNode: "WS-DEV-101",
    targetNode: "Prod API",
    attackRules: [
      { rule: "Developer token read from local credential store", category: "Credential Access", severity: "critical", phase: "execution" },
      { rule: "CI workflow modified outside change window", category: "Persistence", severity: "high", phase: "persistence" },
      { rule: "Build artifact hash changed unexpectedly", category: "Defense Evasion", severity: "high", phase: "execution" },
      { rule: "Package published by unusual automation identity", category: "Impact", severity: "critical", phase: "impact" },
      { rule: "Production API calling unknown telemetry endpoint", category: "Command and Control", severity: "critical", phase: "impact" },
    ],
    attackLogs: [
      { t: "T+00:00", source: "EDR", message: "WS-DEV-101 detected PUA in developer cache; repeated historical false positive", severity: "low" },
      { t: "T+00:07", source: "EDR", message: "token_dump.exe accessed Windows Credential Manager and .npmrc", severity: "critical" },
      { t: "T+00:14", source: "Git", message: "CI workflow changed by svc-deploy from unfamiliar IP", severity: "high" },
      { t: "T+00:22", source: "Build", message: "SRV-BUILD01 produced artifact with unsigned postinstall hook", severity: "high" },
      { t: "T+00:29", source: "Registry", message: "internal-auth-sdk@4.7.2 published outside release window", severity: "critical" },
      { t: "T+00:39", source: "Runtime", message: "Prod API outbound telemetry to 45.227.253.99 every 30 seconds", severity: "critical" },
    ],
    topology: {
      nodes: [
        { id: "dev", label: "DEV-WS-101", role: "developer endpoint", x: 10, y: 35, status: "compromised" },
        { id: "repo", label: "Source Repository", role: "source control", x: 32, y: 28, status: "suspicious" },
        { id: "build", label: "CI Runner", role: "build pipeline", x: 54, y: 35, status: "critical" },
        { id: "registry", label: "Artifact Registry", role: "package store", x: 74, y: 28, status: "critical" },
        { id: "prod", label: "Production API", role: "customer service", x: 90, y: 52, status: "critical" },
        { id: "soc", label: "SOC / EDR", role: "alert console", x: 30, y: 72, status: "noisy" },
      ],
      links: [
        { from: "dev", to: "repo", status: "attack" },
        { from: "repo", to: "build", status: "attack" },
        { from: "build", to: "registry", status: "attack" },
        { from: "registry", to: "prod", status: "attack" },
        { from: "dev", to: "soc", status: "noisy" },
      ],
    },
    outcomeTitle: "Backdoored build reached production",
    outcome: [
      "The noisy developer antivirus alert kept L1 in a familiar false-positive path.",
      "The real issue was not a malware file alone, but token abuse across DevOps systems.",
      "The attack succeeded because each step was small, fast, and distributed across tools.",
    ],
  },
  {
    id: "ddos-attack-flow",
    name: "DDoS Attack Flow",
    shortName: "DDoS Attack",
    summary:
      "A target service is reconned, botnet nodes register with command infrastructure, then SYN, UDP, HTTP, and DNS amplification floods exhaust resources and push the application offline.",
    falsePositiveFocus:
      "Short traffic spike on the public web tier. Similar spikes are often caused by campaigns, crawlers, or CDN cache misses.",
    attackerAutomation:
      "Botnet controller identifies the target, distributes commands, launches simultaneous floods, rotates source IPs, and increases volume until service degradation becomes outage.",
    blastRadius: "Public IP, WAF, load balancer, web tier, DNS, business service availability",
    entryNode: "Public IP",
    targetNode: "WEB-APP-01",
    attackRules: [
      { rule: "Port Scanning and Service Enumeration", category: "Reconnaissance", severity: "medium", phase: "recon" },
      { rule: "Known Botnet IP Communication", category: "Botnet Preparation", severity: "high", phase: "initial" },
      { rule: "Sudden Connection Spike from Many Source IPs", category: "Attack Launch", severity: "high", phase: "execution" },
      { rule: "Excessive SYN/UDP/HTTP Requests", category: "Flooding Phase", severity: "critical", phase: "execution" },
      { rule: "CPU, Memory, Connection Table, and Bandwidth Exhaustion", category: "Resource Exhaustion", severity: "critical", phase: "impact" },
      { rule: "HTTP 5xx Errors and Service Availability Failure", category: "Service Outage", severity: "critical", phase: "impact" },
    ],
    attackLogs: [
      { t: "T+00:00", source: "Firewall", message: "Recon: repeated port scans against 203.0.113.20; ports 80, 443, 53, 8080 probed", severity: "medium" },
      { t: "T+00:05", source: "IDS/IPS", message: "Service enumeration detected; HTTP headers and TLS fingerprinting from 184 source IPs", severity: "medium" },
      { t: "T+00:09", source: "Threat Intel", message: "MISP match: multiple source IPs linked to known botnet infrastructure", severity: "high" },
      { t: "T+00:14", source: "NetFlow", message: "Traffic volume reached 8.7x baseline; 12,480 unique source IPs observed", severity: "high" },
      { t: "T+00:19", source: "Load Balancer", message: "SYN backlog pressure and connection table saturation detected", severity: "critical" },
      { t: "T+00:24", source: "WAF", message: "HTTP GET/POST flood: 146k req/min across /login and /api/search", severity: "critical" },
      { t: "T+00:30", source: "DNS", message: "DNS amplification pattern: query spike and spoofed-source responses", severity: "critical" },
      { t: "T+00:36", source: "APM", message: "Latency p95 18.4s, HTTP 5xx rate 42 percent, request timeouts increasing", severity: "critical" },
      { t: "T+00:42", source: "Availability", message: "Critical business service offline; external health checks failing", severity: "critical" },
    ],
    topology: {
      nodes: [
        { id: "botnet", label: "Botnet Control", role: "many source IPs", x: 8, y: 38, status: "critical" },
        { id: "internet", label: "Internet Edge", role: "traffic flood", x: 24, y: 38, status: "suspicious" },
        { id: "fw", label: "Perimeter Firewall", role: "edge filtering", x: 40, y: 38, status: "noisy" },
        { id: "waf", label: "WAF / CDN", role: "L7 protection", x: 56, y: 26, status: "critical" },
        { id: "lb", label: "Load Balancer", role: "connection table", x: 70, y: 42, status: "critical" },
        { id: "web", label: "Customer Web App", role: "business app", x: 88, y: 42, status: "critical" },
        { id: "soc", label: "SOC / NOC", role: "correlation", x: 48, y: 74, status: "noisy" },
      ],
      links: [
        { from: "botnet", to: "internet", status: "attack" },
        { from: "internet", to: "fw", status: "attack" },
        { from: "fw", to: "waf", status: "attack" },
        { from: "waf", to: "lb", status: "attack" },
        { from: "lb", to: "web", status: "attack" },
        { from: "fw", to: "soc", status: "noisy" },
      ],
    },
    outcomeTitle: "Critical service outage",
    outcome: [
      "The common correlation rule matched: high request rate, many source IPs, high error rate, resource exhaustion, and service availability failure.",
      "Manual triage treated the early spike as possible campaign traffic while the botnet moved from launch to flooding.",
      "Mitigation arrived after resource exhaustion, causing customer-facing downtime.",
    ],
  },
  {
    id: "ransomware-full-flow",
    name: "Ransomware Attack Flow",
    shortName: "Ransomware",
    summary:
      "A ransomware chain moves from initial access through execution, persistence, privilege escalation, defense evasion, credential access, discovery, lateral movement, optional exfiltration, and encryption impact.",
    falsePositiveFocus:
      "Suspicious email and unusual login look like common phishing noise, while the real chain pivots into PowerShell, EDR tampering, credential dumping, and encryption.",
    attackerAutomation:
      "The ransomware operator automates payload execution, persistence, privilege escalation, AV/EDR tampering, LSASS access, AD discovery, SMB spread, exfiltration, VSS deletion, and mass encryption.",
    blastRadius: "User endpoint, domain controller, file shares, backups, business files",
    entryNode: "WS-HR-022",
    targetNode: "SRV-FILE02",
    attackRules: [
      { rule: "Suspicious Email and Malicious Attachment Detected", category: "Initial Access", severity: "medium", phase: "initial" },
      { rule: "Encoded PowerShell Command and Suspicious Process Creation", category: "Execution", severity: "high", phase: "execution" },
      { rule: "Registry Persistence and New Scheduled Task", category: "Persistence", severity: "high", phase: "persistence" },
      { rule: "Security Tool Disabled and Event Logs Cleared", category: "Defense Evasion", severity: "critical", phase: "execution" },
      { rule: "LSASS Memory Access and Credential Dumping", category: "Credential Access", severity: "critical", phase: "execution" },
      { rule: "PsExec, SMB Activity, and Multiple Host Logins", category: "Lateral Movement", severity: "critical", phase: "lateral" },
      { rule: "VSSAdmin Delete Shadows and Mass File Encryption", category: "Impact", severity: "critical", phase: "impact" },
    ],
    attackLogs: [
      { t: "T+00:00", source: "Email Security", message: "Phishing email delivered with malicious attachment invoice_urgent.docm", severity: "medium" },
      { t: "T+00:05", source: "EDR", message: "Macro execution spawned powershell.exe -enc with network download cradle", severity: "high" },
      { t: "T+00:10", source: "Windows", message: "New scheduled task created: OneDriveUpdateCheck running from AppData", severity: "high" },
      { t: "T+00:15", source: "EDR", message: "Security tool disabled, EDR service stop attempted, event logs cleared", severity: "critical" },
      { t: "T+00:20", source: "EDR", message: "LSASS memory access and credential dump artifact detected", severity: "critical" },
      { t: "T+00:25", source: "Network", message: "AD enumeration and network scan across server subnet", severity: "high" },
      { t: "T+00:31", source: "Windows", message: "PsExec usage and remote service creation on SRV-FILE02 and SRV-BACKUP01", severity: "critical" },
      { t: "T+00:36", source: "Proxy", message: "Compressed archive upload to external host 45.227.253.99", severity: "critical" },
      { t: "T+00:42", source: "File Integrity", message: "Mass file modification, high entropy writes, ransom note created", severity: "critical" },
    ],
    topology: {
      nodes: [
        { id: "mail", label: "Mail Gateway", role: "phishing", x: 10, y: 25, status: "suspicious" },
        { id: "ws", label: "HR-WS-022", role: "initial host", x: 30, y: 36, status: "compromised" },
        { id: "dc", label: "AD-DC01", role: "identity services", x: 52, y: 24, status: "critical" },
        { id: "file", label: "File Services Cluster", role: "file shares", x: 74, y: 38, status: "critical" },
        { id: "backup", label: "Backup Vault", role: "backups", x: 74, y: 70, status: "critical" },
        { id: "exfil", label: "External Exfil Host", role: "data exfil", x: 92, y: 18, status: "suspicious" },
        { id: "soc", label: "SOC / EDR", role: "alerts", x: 32, y: 74, status: "noisy" },
      ],
      links: [
        { from: "mail", to: "ws", status: "attack" },
        { from: "ws", to: "dc", status: "attack" },
        { from: "dc", to: "file", status: "attack" },
        { from: "file", to: "backup", status: "attack" },
        { from: "file", to: "exfil", status: "attack" },
        { from: "ws", to: "soc", status: "noisy" },
      ],
    },
    outcomeTitle: "Ransomware incident reached encryption",
    outcome: [
      "High-confidence ransomware conditions matched: suspicious PowerShell, security tool disabled, credential dumping, lateral movement, shadow copy deletion, and mass encryption.",
      "The L1 queue saw each alert separately instead of one critical ransomware chain.",
      "Containment was delayed until after file encryption and service disruption.",
    ],
  },
  {
    id: "lateral-movement-flow",
    name: "Lateral Movement Attack Flow",
    shortName: "Lateral Movement",
    summary:
      "After an initial compromise, the attacker dumps credentials, discovers the network, authenticates remotely, and spreads to additional hosts using SMB, PsExec, and repeated logins.",
    falsePositiveFocus:
      "Multiple host logins from an admin account look like normal IT maintenance, delaying investigation while credential abuse spreads.",
    attackerAutomation:
      "Credential dump, network discovery, remote authentication, SMB access, PsExec execution, and remote service creation are automated across the internal subnet.",
    blastRadius: "Admin workstation, server subnet, file server, domain controller",
    entryNode: "WS-IT-009",
    targetNode: "SRV-DC01",
    attackRules: [
      { rule: "Credential Dumping Activity", category: "Credential Access", severity: "critical", phase: "execution" },
      { rule: "Network Scan Detected", category: "Discovery", severity: "high", phase: "recon" },
      { rule: "Remote Authentication from Compromised Host", category: "Lateral Movement", severity: "high", phase: "lateral" },
      { rule: "PsExec Usage and Remote Service Creation", category: "Lateral Movement", severity: "critical", phase: "lateral" },
      { rule: "SMB Activity and Multiple Host Logins", category: "Spread", severity: "critical", phase: "impact" },
    ],
    attackLogs: [
      { t: "T+00:00", source: "EDR", message: "Credential dumping tool accessed LSASS on WS-IT-009", severity: "critical" },
      { t: "T+00:07", source: "Network", message: "Internal network scan detected across 10.24.12.0/24", severity: "high" },
      { t: "T+00:13", source: "Windows", message: "Remote authentication to SRV-FILE02 using it.admin token", severity: "high" },
      { t: "T+00:19", source: "EDR", message: "PsExec service created on SRV-FILE02", severity: "critical" },
      { t: "T+00:26", source: "SMB", message: "Admin share access across 17 hosts in 90 seconds", severity: "critical" },
      { t: "T+00:34", source: "Identity", message: "Multiple host logins and privileged session creation on SRV-DC01", severity: "critical" },
      { t: "T+00:42", source: "SIEM", message: "Lateral movement incident confirmed across server subnet", severity: "critical" },
    ],
    topology: {
      nodes: [
        { id: "it", label: "IT-WS-009", role: "initial compromise", x: 12, y: 38, status: "compromised" },
        { id: "subnet", label: "Server VLAN", role: "discovery", x: 32, y: 38, status: "suspicious" },
        { id: "file", label: "File Services Cluster", role: "SMB target", x: 54, y: 24, status: "critical" },
        { id: "app", label: "Application Server", role: "remote service", x: 54, y: 56, status: "critical" },
        { id: "dc", label: "AD-DC01", role: "domain controller", x: 80, y: 38, status: "critical" },
        { id: "soc", label: "SOC / SIEM", role: "alert queue", x: 32, y: 76, status: "noisy" },
      ],
      links: [
        { from: "it", to: "subnet", status: "attack" },
        { from: "subnet", to: "file", status: "attack" },
        { from: "subnet", to: "app", status: "attack" },
        { from: "file", to: "dc", status: "attack" },
        { from: "app", to: "dc", status: "attack" },
        { from: "it", to: "soc", status: "noisy" },
      ],
    },
    outcomeTitle: "Attacker spread across internal hosts",
    outcome: [
      "Credential dumping, network scan, PsExec usage, SMB activity, and multiple host logins formed one lateral movement incident.",
      "Manual L1 triage treated the events as separate admin and network alerts.",
      "The attacker reached additional hosts before containment started.",
    ],
  },
].sort((a, b) => {
  const priority = ["ransomware-full-flow", "ddos-attack-flow", "lateral-movement-flow"];
  const aIndex = priority.indexOf(a.id);
  const bIndex = priority.indexOf(b.id);
  return (aIndex === -1 ? 99 : aIndex) - (bIndex === -1 ? 99 : bIndex);
});

export function randomIP() {
  return `10.24.${Math.floor(Math.random() * 50)}.${Math.floor(Math.random() * 255)}`;
}

export function pick<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}
