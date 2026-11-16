"""Tools available to the triage agent."""

import json
from pathlib import Path

from langchain_core.tools import tool

# Load MITRE ATT&CK technique descriptions (subset for common techniques).
_TECHNIQUE_DB: dict[str, dict] = {}
_TECHNIQUE_DB_PATH = Path(__file__).parent.parent.parent / "data" / "attack_techniques.json"


def _load_technique_db() -> dict[str, dict]:
    """Load the technique database lazily."""
    global _TECHNIQUE_DB
    if not _TECHNIQUE_DB and _TECHNIQUE_DB_PATH.exists():
        with open(_TECHNIQUE_DB_PATH) as f:
            _TECHNIQUE_DB = json.load(f)
    return _TECHNIQUE_DB


@tool
def lookup_technique(technique_id: str) -> str:
    """Look up a MITRE ATT&CK technique by ID (e.g. T1053.005).

    Returns the technique name, tactic, description, and typical severity.
    """
    db = _load_technique_db()
    tech_id = technique_id.upper().strip()
    if tech_id in db:
        entry = db[tech_id]
        return json.dumps(entry, indent=2)
    # Try parent technique (e.g. T1053 from T1053.005)
    parent = tech_id.split(".")[0]
    if parent in db:
        entry = db[parent]
        parent_json = json.dumps(entry, indent=2)
        return f"Sub-technique {tech_id} not found. Parent technique:\n{parent_json}"
    return f"Technique {tech_id} not found in the database."


@tool
def analyse_event_fields(event_json: str) -> str:
    """Analyse key fields from a Windows event log entry.

    Extracts process names, command lines, user context, and network info
    to help determine if the event is suspicious or benign.
    """
    try:
        event = json.loads(event_json) if isinstance(event_json, str) else event_json
    except (json.JSONDecodeError, TypeError):
        return "Error: could not parse event JSON."

    findings = []

    # Process info
    image = event.get("Image") or event.get("NewProcessName") or ""
    parent = event.get("ParentImage") or ""
    cmd = event.get("CommandLine") or ""
    user = event.get("User") or event.get("SubjectUserName") or event.get("TargetUserName") or ""

    if image:
        proc_name = image.split("\\")[-1].lower()
        findings.append(f"Process: {proc_name}")
        # Known system processes
        system_procs = {
            "svchost.exe", "services.exe", "lsass.exe", "csrss.exe",
            "explorer.exe", "taskhostw.exe", "wmiprvse.exe", "conhost.exe",
        }
        if proc_name in system_procs:
            findings.append("  -> Known Windows system process (likely benign)")
        # Suspicious indicators
        suspicious = ["powershell", "cmd.exe", "wscript", "cscript", "mshta", "regsvr32"]
        if any(s in proc_name for s in suspicious):
            findings.append("  -> Process commonly abused by attackers")

    if parent:
        findings.append(f"Parent process: {parent.split(chr(92))[-1]}")

    if cmd:
        cmd_lower = cmd.lower()
        findings.append(f"Command line: {cmd[:200]}")
        # Obfuscation indicators
        if any(ind in cmd_lower for ind in ["-enc", "-encodedcommand", "base64", "iex", "invoke-"]):
            findings.append("  -> Contains obfuscation/execution indicators (suspicious)")
        if any(ind in cmd_lower for ind in ["-nop", "-w hidden", "-windowstyle hidden"]):
            findings.append("  -> Hidden execution flags (suspicious)")

    if user:
        findings.append(f"User: {user}")
        if user.upper() == "SYSTEM":
            findings.append("  -> Running as SYSTEM (elevated)")

    # Network info
    src_ip = event.get("SourceIp") or event.get("SourceAddress") or ""
    dst_ip = event.get("DestinationIp") or event.get("DestinationAddress") or ""
    if src_ip or dst_ip:
        findings.append(f"Network: {src_ip} -> {dst_ip}")

    # EventID context
    eid = event.get("EventID")
    if eid:
        findings.append(f"EventID: {eid}")
        notable_eids = {
            1: "Process creation (Sysmon)",
            3: "Network connection (Sysmon)",
            7: "Image loaded (Sysmon)",
            4624: "Successful logon",
            4625: "Failed logon",
            4688: "Process creation (Security)",
            4698: "Scheduled task created",
            4720: "User account created",
            4732: "Member added to security group",
            5156: "WFP connection allowed",
            5158: "WFP bind allowed",
        }
        if int(eid) in notable_eids:
            findings.append(f"  -> {notable_eids[int(eid)]}")

    if not findings:
        return "No significant fields found in this event."
    return "\n".join(findings)


@tool
def check_ip_reputation(ip_address: str) -> str:
    """Check if an IP address is internal (RFC1918), loopback, or external.

    Flags known suspicious patterns and provides network context
    to help determine if network activity is expected.
    """
    import ipaddress

    ip_str = ip_address.strip()
    if not ip_str or ip_str == "-":
        return "No IP address provided."

    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return f"Invalid IP address: {ip_str}"

    findings = [f"IP: {ip_str}"]

    if ip.is_loopback:
        findings.append("  -> Loopback address (localhost traffic, benign)")
    elif ip.is_private:
        findings.append("  -> RFC1918 private address (internal network)")
        # Flag unusual internal ranges
        if ip_str.startswith("10."):
            findings.append("  -> Corporate/datacenter range")
        elif ip_str.startswith("192.168."):
            findings.append("  -> Workstation/home network range")
        elif ip_str.startswith("172."):
            findings.append("  -> Internal services range")
    elif ip.is_reserved or ip.is_multicast:
        findings.append("  -> Reserved/multicast address")
    else:
        findings.append("  -> External (public) IP address")
        findings.append(
            "  -> Recommendation: check against threat intel feeds"
            " (VirusTotal, AbuseIPDB)"
        )

    return "\n".join(findings)


@tool
def enrich_user_context(username: str) -> str:
    """Analyse a Windows username to determine account type and risk level.

    Identifies service accounts, built-in accounts, privileged users,
    and normal user accounts to provide context for triage decisions.
    """
    if not username or username.strip() in ("-", ""):
        return "No username provided."

    user = username.strip()
    user_upper = user.upper()
    findings = [f"User: {user}"]

    # Built-in system accounts
    system_accounts = {
        "SYSTEM": "NT AUTHORITY\\SYSTEM — highest privilege Windows account",
        "LOCAL SERVICE": "Low-privilege service account for local services",
        "NETWORK SERVICE": "Low-privilege account for network-facing services",
        "ANONYMOUS LOGON": "Unauthenticated connection (suspicious if unexpected)",
    }

    for acct, desc in system_accounts.items():
        if acct in user_upper:
            findings.append(f"  -> Built-in account: {desc}")
            if acct == "SYSTEM":
                findings.append(
                    "  -> Risk: SYSTEM running user tools"
                    " (e.g. PowerShell, cmd) is suspicious"
                )
            elif acct == "ANONYMOUS LOGON":
                findings.append("  -> Risk: may indicate unauthorized access")
            return "\n".join(findings)

    # Service account patterns
    svc_patterns = ["svc_", "svc-", "service_", "sa_", "sa-", "$"]
    if any(user.lower().startswith(p) for p in svc_patterns[:-1]):
        findings.append("  -> Appears to be a service account (naming convention)")
        findings.append("  -> Verify this account should run the observed process")
        return "\n".join(findings)
    if user.endswith("$"):
        findings.append("  -> Machine account (computer object in AD)")
        findings.append("  -> Normal for machine-to-machine authentication")
        return "\n".join(findings)

    # Admin patterns
    admin_patterns = ["admin", "root", "dba", "operator"]
    if any(p in user.lower() for p in admin_patterns):
        findings.append("  -> Potentially privileged account (admin-like name)")
        findings.append("  -> Higher scrutiny warranted for unusual activity")
    else:
        findings.append("  -> Standard user account")
        findings.append("  -> Check if activity matches user's normal role")

    return "\n".join(findings)


TRIAGE_TOOLS = [
    lookup_technique,
    analyse_event_fields,
    check_ip_reputation,
    enrich_user_context,
]
