"""
Detection rule library — curated real Sigma rules with ATT&CK metadata.
Optionally augmented by fetching rule names from the SigmaHQ GitHub repo.
"""

import os
import logging
import requests

logger = logging.getLogger(__name__)

# Curated set of real, well-known Sigma rules with full ATT&CK metadata.
# Source: https://github.com/SigmaHQ/sigma
CURATED_RULES = [
    {
        "id": "SIG-WIN-001",
        "name": "Suspicious PowerShell Encoded Command",
        "description": "Detects PowerShell invocation with Base64-encoded command (-EncodedCommand / -enc). Commonly used to obfuscate malicious payloads.",
        "severity": "high",
        "technique": "T1059.001",
        "tactic": "Execution",
        "sigma_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_encoded_cmd.yml",
        "common_fp": "SCCM software deployment, admin automation scripts, legitimate scheduled tasks",
    },
    {
        "id": "SIG-WIN-002",
        "name": "LSASS Memory Access",
        "description": "Detects process access to LSASS memory. Used by credential dumping tools such as Mimikatz, ProcDump, and Invoke-Mimikatz.",
        "severity": "critical",
        "technique": "T1003.001",
        "tactic": "Credential Access",
        "sigma_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_access/proc_access_win_lsass_access.yml",
        "common_fp": "AV/EDR products, WerFault.exe, backup agents accessing LSASS",
    },
    {
        "id": "SIG-WIN-003",
        "name": "Multiple Failed Login Attempts",
        "description": "Detects a high volume of failed authentication events (Event ID 4625) from a single source, indicating a brute force or password spray attempt.",
        "severity": "medium",
        "technique": "T1110.001",
        "tactic": "Credential Access",
        "sigma_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_susp_failed_logons_explicit_credentials.yml",
        "common_fp": "Monitoring services, health check scripts, misconfigured service accounts",
    },
    {
        "id": "SIG-WIN-004",
        "name": "Unusual Outbound Network Traffic",
        "description": "Detects outbound connections to unusual ports or high-volume data transfer from internal hosts to external destinations.",
        "severity": "medium",
        "technique": "T1048",
        "tactic": "Exfiltration",
        "sigma_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/network/net_firewall_high_volume_outbound.yml",
        "common_fp": "Backup agents, cloud sync tools (OneDrive, Dropbox), software update services",
    },
    {
        "id": "SIG-WIN-005",
        "name": "Process Injection via CreateRemoteThread",
        "description": "Detects CreateRemoteThread API calls targeting other processes, a common technique used by malware to inject shellcode.",
        "severity": "high",
        "technique": "T1055.003",
        "tactic": "Defense Evasion",
        "sigma_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_access/proc_access_win_createremotethread_injecting_target.yml",
        "common_fp": "Debuggers (x64dbg, WinDbg), developer tools, JetBrains IDEs, some AV products",
    },
    {
        "id": "SIG-WIN-006",
        "name": "Scheduled Task Creation via Schtasks",
        "description": "Detects scheduled task creation using schtasks.exe, often used for persistence by malware.",
        "severity": "medium",
        "technique": "T1053.005",
        "tactic": "Persistence",
        "sigma_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_schtasks_creation.yml",
        "common_fp": "Software installers, IT management tools, Windows Update, legitimate admin scripts",
    },
    {
        "id": "SIG-WIN-007",
        "name": "Registry Run Key Modification",
        "description": "Detects modifications to HKLM/HKCU Run keys, a classic persistence mechanism used by malware to survive reboots.",
        "severity": "medium",
        "technique": "T1547.001",
        "tactic": "Persistence",
        "sigma_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_run_key_startup.yml",
        "common_fp": "Software installers, legitimate startup applications, endpoint agents",
    },
    {
        "id": "SIG-WIN-008",
        "name": "Certutil Abuse for File Download",
        "description": "Detects use of certutil.exe to download files from the internet, a common LOLBAS technique.",
        "severity": "high",
        "technique": "T1105",
        "tactic": "Command and Control",
        "sigma_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_certutil_download.yml",
        "common_fp": "Certificate management scripts, PKI admin tasks",
    },
    {
        "id": "SIG-WIN-009",
        "name": "WMI Spawning Process",
        "description": "Detects processes spawned by WMI (wmiprvse.exe), which attackers use for lateral movement and remote execution.",
        "severity": "high",
        "technique": "T1047",
        "tactic": "Execution",
        "sigma_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_wmi_susp_scripting.yml",
        "common_fp": "SCCM, monitoring agents, system management tools using WMI",
    },
    {
        "id": "SIG-WIN-010",
        "name": "Pass the Hash Activity",
        "description": "Detects Pass-the-Hash attacks by identifying NTLM authentication with mismatched logon types (Event ID 4624 Type 3 with blank password).",
        "severity": "critical",
        "technique": "T1550.002",
        "tactic": "Lateral Movement",
        "sigma_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_pass_the_hash.yml",
        "common_fp": "Rarely a FP — investigate any hits",
    },
    {
        "id": "SIG-WIN-011",
        "name": "Suspicious Use of PsExec",
        "description": "Detects execution of PsExec or PsExec-like tools, commonly used by attackers for lateral movement.",
        "severity": "high",
        "technique": "T1569.002",
        "tactic": "Lateral Movement",
        "sigma_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_sysinternals_psexec.yml",
        "common_fp": "IT admins using PsExec for remote administration, software deployment",
    },
    {
        "id": "SIG-WIN-012",
        "name": "Privilege Escalation via Token Impersonation",
        "description": "Detects token impersonation/theft used to escalate privileges, commonly seen in post-exploitation frameworks.",
        "severity": "critical",
        "technique": "T1134.001",
        "tactic": "Privilege Escalation",
        "sigma_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_access/proc_access_win_susp_token_impersonation.yml",
        "common_fp": "Security software, some IIS worker processes",
    },
    {
        "id": "SIG-NET-001",
        "name": "DNS Query for Suspicious TLD",
        "description": "Detects DNS queries to uncommon top-level domains associated with C2 infrastructure or domain generation algorithms.",
        "severity": "medium",
        "technique": "T1568.002",
        "tactic": "Command and Control",
        "sigma_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/network/dns/net_dns_susp_tld.yml",
        "common_fp": "Legitimate software using .xyz, .io, or newer TLDs",
    },
    {
        "id": "SIG-NET-002",
        "name": "Potential DNS Tunneling",
        "description": "Detects abnormally large DNS queries or high-frequency DNS requests to the same domain, indicating potential data exfiltration via DNS.",
        "severity": "medium",
        "technique": "T1071.004",
        "tactic": "Command and Control",
        "sigma_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/network/dns/net_dns_tunnel.yml",
        "common_fp": "DNS-based load balancers, CDN health checks, some VPN solutions",
    },
    {
        "id": "SIG-WIN-013",
        "name": "Shadow Copy Deletion",
        "description": "Detects deletion of volume shadow copies using vssadmin, wmic, or PowerShell — a key ransomware indicator.",
        "severity": "critical",
        "technique": "T1490",
        "tactic": "Impact",
        "sigma_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_vssadmin_delete_shadows.yml",
        "common_fp": "Disk cleanup scripts (rare), some backup tools during reconfiguration",
    },
    {
        "id": "SIG-WIN-014",
        "name": "Unauthorized Software Installation",
        "description": "Detects installation of software by non-admin users or from unusual locations, potentially indicating policy violation or malware dropper.",
        "severity": "low",
        "technique": "T1072",
        "tactic": "Execution",
        "sigma_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_msiexec_install_quiet.yml",
        "common_fp": "Self-updating applications, developer tooling, user-space package managers",
    },
    {
        "id": "SIG-WIN-015",
        "name": "Anomalous User Account Behaviour",
        "description": "Detects user accounts performing actions outside their normal baseline — logins at unusual times, from unusual locations, or accessing new resources.",
        "severity": "medium",
        "technique": "T1078",
        "tactic": "Initial Access",
        "sigma_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_susp_logon.yml",
        "common_fp": "Travel, remote work, shift changes, service account reuse",
    },
    {
        "id": "SIG-WIN-016",
        "name": "Suspicious Registry Modification",
        "description": "Detects modifications to security-sensitive registry keys including Winlogon, AppInit_DLLs, and LSA settings.",
        "severity": "high",
        "technique": "T1112",
        "tactic": "Defense Evasion",
        "sigma_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_susp_reg_persist.yml",
        "common_fp": "AV installations, Windows updates, legitimate software modifying AppInit",
    },
    {
        "id": "SIG-WIN-017",
        "name": "Brute Force Attack Detected",
        "description": "Detects rapid repeated authentication failures followed by a successful login from the same source, indicating credential brute force.",
        "severity": "high",
        "technique": "T1110",
        "tactic": "Credential Access",
        "sigma_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_susp_failed_logon.yml",
        "common_fp": "Service accounts with expired passwords, users mistyping passwords",
    },
    {
        "id": "SIG-WIN-018",
        "name": "PowerShell Downloading Payload",
        "description": "Detects PowerShell using Net.WebClient, Invoke-WebRequest, or Start-BitsTransfer to download content from the internet.",
        "severity": "high",
        "technique": "T1059.001",
        "tactic": "Execution",
        "sigma_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_download.yml",
        "common_fp": "Software deployment scripts, Windows module installation, legitimate admin tooling",
    },
]

# Build a lookup dict by name for fast access
_RULE_BY_NAME = {r["name"]: r for r in CURATED_RULES}


def get_all_rules() -> list:
    return CURATED_RULES


def get_rule_by_name(name: str) -> dict:
    return _RULE_BY_NAME.get(name, {})


def fetch_sigma_rules_from_github(token: str = "") -> list:
    """
    Fetch rule names from the SigmaHQ GitHub repo file tree.
    Returns a list of rule name strings parsed from filenames.
    Requires no auth but is rate-limited to 60 req/hr without a token.
    Set GITHUB_TOKEN env var to increase to 5000 req/hr.
    """
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        resp = requests.get(
            "https://api.github.com/repos/SigmaHQ/sigma/git/trees/master?recursive=1",
            headers=headers,
            timeout=10,
        )
        if resp.status_code != 200:
            logger.warning("SigmaHQ GitHub API returned %s", resp.status_code)
            return []

        tree = resp.json().get("tree", [])
        rule_files = [
            f["path"] for f in tree
            if f["path"].startswith("rules/") and f["path"].endswith(".yml")
        ]

        names = []
        for path in rule_files[:200]:
            filename = path.split("/")[-1].replace(".yml", "")
            # Convert snake_case filename to Title Case rule name
            name = " ".join(w.capitalize() for w in filename.split("_")
                            if w not in ("win", "proc", "creation", "net", "registry",
                                         "set", "builtin", "security", "susp"))
            if name:
                names.append(name)

        logger.info("Fetched %d rule names from SigmaHQ GitHub", len(names))
        return names

    except Exception as e:
        logger.warning("Failed to fetch from SigmaHQ GitHub: %s", e)
        return []
