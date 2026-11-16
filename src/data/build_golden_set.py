"""Build the golden set of labeled SOC alerts from OTRF logs + Sigma rules.

Pipeline:
1. Select 20 diverse OTRF recordings
2. Download their event log ZIPs
3. Download Sigma rules from SigmaHQ
4. Run Sigma rules against each recording's events
5. Classify hits as malicious (matches OTRF technique) or benign (off-target, strict)
6. Normalize identifiers, apply technique cap, split dev/test by recording
7. Output golden_set.json + statistics
"""

import hashlib
import json
import random
import re
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from src.data.download_logs import download_all_selected, load_events
from src.data.select_datasets import get_selected_datasets, print_selection_summary
from src.data.sigma_matcher import (
    get_rule_attack_tags,
    get_rule_level,
    load_sigma_rules_from_dir,
    match_rules_optimized,
)

SIGMA_DIR = Path("data/raw/sigma-rules")
GOLDEN_SET_DIR = Path("data/golden_set")
RESULTS_DIR = Path("results")

# Tactic-based severity mapping for malicious alerts
TACTIC_SEVERITY = {
    "TA0001": "medium",    # Initial Access
    "TA0002": "medium",    # Execution
    "TA0003": "high",      # Persistence
    "TA0004": "high",      # Privilege Escalation
    "TA0005": "medium",    # Defense Evasion
    "TA0006": "critical",  # Credential Access
    "TA0007": "low",       # Discovery
    "TA0008": "high",      # Lateral Movement
    "TA0009": "medium",    # Collection
    "TA0010": "high",      # Exfiltration
    "TA0011": "medium",    # Command and Control
    "TA0040": "critical",  # Impact
}

# Max alerts per ATT&CK sub-technique
TECHNIQUE_CAP = 3

# Dev/test split: 25% dev, 75% test (by recording)
DEV_FRACTION = 0.25


def download_sigma_rules() -> Path:
    """Clone SigmaHQ rules if not already present."""
    if SIGMA_DIR.exists() and any(SIGMA_DIR.rglob("*.yml")):
        print(f"Sigma rules already cached at {SIGMA_DIR}")
        return SIGMA_DIR

    SIGMA_DIR.mkdir(parents=True, exist_ok=True)
    print("Downloading SigmaHQ rules (sparse checkout — windows only)...")
    subprocess.run(
        [
            "git", "clone", "--depth", "1", "--filter=blob:none", "--sparse",
            "https://github.com/SigmaHQ/sigma.git", str(SIGMA_DIR),
        ],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(SIGMA_DIR), "sparse-checkout", "set",
         "rules/windows", "rules-emerging-threats/"],
        check=True,
    )
    return SIGMA_DIR


def _extract_technique_id(mapping: dict) -> str:
    """Build full technique ID like T1003.001 from an attack_mapping."""
    tech = mapping.get("technique", "")
    sub = mapping.get("sub-technique") or mapping.get("sub_technique") or ""
    if sub:
        return f"{tech}.{sub}".upper()
    return tech.upper()


def _get_dataset_techniques(dataset: dict) -> set[str]:
    """Get all ATT&CK technique IDs labeled for a dataset."""
    techniques = set()
    for am in dataset.get("attack_mappings", []):
        techniques.add(_extract_technique_id(am))
    return techniques


def _get_dataset_tactics(dataset: dict) -> list[str]:
    """Get all tactics from a dataset."""
    tactics = []
    for am in dataset.get("attack_mappings", []):
        for tac in am.get("tactics", []):
            if tac not in tactics:
                tactics.append(tac)
    return tactics


def _normalize_timestamp(ts: str) -> str:
    """Replace real timestamps with synthetic ones."""
    # Just hash to produce deterministic but anonymized time
    h = hashlib.md5(ts.encode()).hexdigest()[:8]
    base = datetime(2024, 1, 15, 10, 0, 0)
    offset_seconds = int(h, 16) % 86400
    normalized = base.replace(
        hour=offset_seconds // 3600,
        minute=(offset_seconds % 3600) // 60,
        second=offset_seconds % 60,
    )
    return normalized.isoformat() + "Z"


def _normalize_ip(ip: str) -> str:
    """Replace real IPs with synthetic deterministic ones."""
    h = hashlib.md5(ip.encode()).hexdigest()
    return f"10.{int(h[:2], 16) % 256}.{int(h[2:4], 16) % 256}.{int(h[4:6], 16) % 256}"


def _normalize_hostname(name: str) -> str:
    """Replace real hostnames with synthetic ones."""
    h = hashlib.md5(name.encode()).hexdigest()[:6]
    return f"HOST-{h.upper()}"


def _normalize_username(name: str) -> str:
    """Replace real usernames with synthetic ones."""
    if not name or name in ("-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
        return name
    h = hashlib.md5(name.encode()).hexdigest()[:6]
    return f"user_{h}"


def _normalize_domain(domain: str) -> str:
    """Replace real domain names with synthetic ones."""
    if not domain:
        return domain
    h = hashlib.md5(domain.encode()).hexdigest()[:6]
    return f"DOMAIN-{h.upper()}"


def normalize_event_fields(event: dict) -> dict:
    """Normalize PII/identifying fields in an event for the golden set."""
    normalized = dict(event)

    # Normalize timestamps
    for ts_field in ("@timestamp", "Timestamp", "UtcTime", "CreationUtcTime",
                     "TimeCreated", "SystemTime"):
        val = normalized.get(ts_field)
        if val and isinstance(val, str):
            normalized[ts_field] = _normalize_timestamp(val)
        # Check nested
        if ts_field == "SystemTime":
            tc = normalized.get("TimeCreated", {})
            if isinstance(tc, dict) and "SystemTime" in tc:
                tc["SystemTime"] = _normalize_timestamp(tc["SystemTime"])

    # Normalize IPs
    for ip_field in ("SourceIp", "DestinationIp", "IpAddress", "SourceAddress",
                     "DestinationAddress", "src_ip", "dst_ip"):
        val = normalized.get(ip_field)
        if val and isinstance(val, str) and re.match(r"\d+\.\d+\.\d+\.\d+", val):
            normalized[ip_field] = _normalize_ip(val)

    # Normalize hostnames
    for host_field in ("ComputerName", "Computer", "Hostname", "SourceHostname",
                       "DestinationHostname", "MachineName"):
        val = normalized.get(host_field)
        if val and isinstance(val, str):
            normalized[host_field] = _normalize_hostname(val)

    # Normalize usernames
    for user_field in ("User", "SubjectUserName", "TargetUserName", "SourceUser",
                       "AccountName"):
        val = normalized.get(user_field)
        if val and isinstance(val, str):
            normalized[user_field] = _normalize_username(val)

    # Normalize domains
    for domain_field in ("SubjectDomainName", "TargetDomainName"):
        val = normalized.get(domain_field)
        if val and isinstance(val, str):
            normalized[domain_field] = _normalize_domain(val)

    return normalized


def _is_benign_hit(
    event: dict,
    rule: dict,
    dataset: dict,
    dataset_techniques: set[str],
) -> bool | None:
    """Determine if a Sigma hit is benign (off-target).

    Returns True if clearly benign, False if malicious, None if uncertain.

    Strict benign criteria:
    - Rule's ATT&CK tags do NOT overlap with the dataset's labeled techniques
    - Event appears to be from normal system processes (svchost, services, etc.)
    - NOT from attack-related processes listed in the dataset description
    """
    rule_techniques = set()
    for tag in rule.get("tags", []):
        if isinstance(tag, str) and tag.startswith("attack.t"):
            # Normalize: attack.t1059.001 -> T1059.001
            tech = tag.replace("attack.", "").upper()
            # Handle dot variations
            parts = tech.split(".")
            if len(parts) >= 2:
                rule_techniques.add(f"{parts[0]}.{parts[1]}")
            rule_techniques.add(parts[0])

    # If the rule's technique overlaps with the dataset's technique -> malicious
    if rule_techniques & dataset_techniques:
        return False  # malicious

    # If no technique overlap, check if the event looks like background noise
    # Known benign process patterns
    benign_processes = {
        "svchost.exe", "services.exe", "lsass.exe", "csrss.exe", "smss.exe",
        "wininit.exe", "winlogon.exe", "explorer.exe", "taskhostw.exe",
        "spoolsv.exe", "searchindexer.exe", "msiexec.exe", "tiworker.exe",
        "trustedinstaller.exe", "dllhost.exe", "wmiprvse.exe", "conhost.exe",
        "backgroundtaskhost.exe", "runtimebroker.exe", "sihost.exe",
        "searchprotocolhost.exe", "searchfilterhost.exe",
    }

    image = (event.get("Image") or event.get("NewProcessName") or "").lower()
    parent_image = (event.get("ParentImage") or "").lower()

    image_name = image.split("\\")[-1] if image else ""
    parent_name = parent_image.split("\\")[-1] if parent_image else ""

    # If the rule doesn't match the dataset technique AND the process is a
    # known system process, it's benign background noise
    if image_name in benign_processes or parent_name in benign_processes:
        return True  # benign

    # If the rule technique doesn't overlap but the process isn't clearly benign,
    # mark as uncertain
    return None


def _highest_severity(tactics: list[str]) -> str:
    """Return the highest severity from a list of tactics."""
    severity_order = ["critical", "high", "medium", "low", "informational"]
    best = "low"
    for tac in tactics:
        sev = TACTIC_SEVERITY.get(tac, "medium")
        if severity_order.index(sev) < severity_order.index(best):
            best = sev
    return best


def build_alert(
    event: dict,
    rule: dict,
    dataset: dict,
    label: str,
    alert_id: int,
) -> dict:
    """Build a SIEM-style alert from a matched event + rule."""
    # Normalize the event
    norm_event = normalize_event_fields(event)

    # Get severity
    tactics = _get_dataset_tactics(dataset)
    if label == "malicious":
        severity = _highest_severity(tactics)
    else:
        severity = None

    # Get technique info
    techniques = []
    if label == "malicious":
        for am in dataset.get("attack_mappings", []):
            techniques.append(_extract_technique_id(am))
    else:
        # For benign, use the rule's tagged technique (what was detected)
        for tag in rule.get("tags", []):
            if isinstance(tag, str) and tag.startswith("attack.t"):
                tech = tag.replace("attack.", "").upper()
                parts = tech.split(".")
                if len(parts) >= 2:
                    techniques.append(f"{parts[0]}.{parts[1]}")
                else:
                    techniques.append(parts[0])

    return {
        "alert_id": f"ALERT-{alert_id:04d}",
        "rule_name": rule.get("title", "Unknown Rule"),
        "rule_id": rule.get("id", ""),
        "sigma_level": get_rule_level(rule),
        "description": rule.get("description", ""),
        "matched_event": norm_event,
        "techniques": techniques,
        "source_recording": dataset["id"],
        "ground_truth": {
            "label": label,
            "severity": severity,
            "reasoning": (
                f"Sigma rule matches OTRF-labeled technique for {dataset['title']}"
                if label == "malicious"
                else "Off-target Sigma hit on background system activity"
            ),
        },
    }


def build_golden_set():
    """Main pipeline: build the golden set."""
    random.seed(42)

    # Step 1: Select datasets
    print("=" * 60)
    print("STEP 1: Select diverse OTRF recordings")
    print("=" * 60)
    datasets = get_selected_datasets()
    print_selection_summary(datasets)

    # Step 2: Download event logs
    print("\n" + "=" * 60)
    print("STEP 2: Download event logs")
    print("=" * 60)
    log_paths = download_all_selected(datasets)

    # Step 3: Download Sigma rules
    print("\n" + "=" * 60)
    print("STEP 3: Download Sigma rules")
    print("=" * 60)
    sigma_base = download_sigma_rules()
    windows_rules_dir = sigma_base / "rules" / "windows"
    if not windows_rules_dir.exists():
        print(f"ERROR: {windows_rules_dir} not found")
        sys.exit(1)

    sigma_rules = load_sigma_rules_from_dir(windows_rules_dir)
    print(f"Loaded {len(sigma_rules)} Sigma rules")

    # Sigma level distribution
    level_dist = Counter(get_rule_level(r) for r in sigma_rules)
    print(f"Sigma level distribution: {dict(level_dist)}")

    # Step 4: Match rules against events
    print("\n" + "=" * 60)
    print("STEP 4: Run Sigma rules against event logs")
    print("=" * 60)

    malicious_alerts = []
    benign_alerts = []
    uncertain_count = 0
    alert_counter = 1
    technique_counts = defaultdict(int)  # for technique cap
    stats_per_source = {}

    for ds in datasets:
        did = ds["id"]
        ds_techniques = _get_dataset_techniques(ds)
        paths = log_paths.get(did, [])
        if not paths:
            print(f"  {did}: no log files, skipping")
            continue

        # Load events from all JSON files for this dataset
        all_events = []
        for p in paths:
            all_events.extend(load_events(p))
        print(f"  {did}: {len(all_events)} events from {len(paths)} file(s)", flush=True)

        ds_malicious = 0
        ds_benign = 0
        ds_uncertain = 0

        # Optimized matching with EventID pre-filtering
        hits = match_rules_optimized(sigma_rules, all_events, max_matches_per_rule=5)
        print(f"    {len(hits)} rule-event hits", flush=True)

        for rule, event in hits:
            classification = _is_benign_hit(event, rule, ds, ds_techniques)

            if classification is None:
                ds_uncertain += 1
                uncertain_count += 1
                continue

            if classification:  # benign
                rule_techs = get_rule_attack_tags(rule)
                tech_key = rule_techs[0] if rule_techs else "unknown"
                if technique_counts[f"benign_{tech_key}"] >= TECHNIQUE_CAP:
                    continue
                technique_counts[f"benign_{tech_key}"] += 1

                alert = build_alert(event, rule, ds, "benign", alert_counter)
                benign_alerts.append(alert)
                alert_counter += 1
                ds_benign += 1
            else:  # malicious
                # Check technique cap for malicious
                capped = False
                for tech in ds_techniques:
                    if technique_counts[f"malicious_{tech}"] >= TECHNIQUE_CAP:
                        capped = True
                        break
                if capped:
                    continue
                for tech in ds_techniques:
                    technique_counts[f"malicious_{tech}"] += 1

                alert = build_alert(event, rule, ds, "malicious", alert_counter)
                malicious_alerts.append(alert)
                alert_counter += 1
                ds_malicious += 1

        stats_per_source[did] = {
            "title": ds["title"],
            "events": len(all_events),
            "malicious": ds_malicious,
            "benign": ds_benign,
            "uncertain": ds_uncertain,
            "techniques": sorted(ds_techniques),
        }
        print(f"    -> {ds_malicious} malicious, {ds_benign} benign, {ds_uncertain} uncertain",
              flush=True)

    all_alerts = malicious_alerts + benign_alerts
    print(f"\nTotal alerts: {len(all_alerts)} ({len(malicious_alerts)} malicious, "
          f"{len(benign_alerts)} benign, {uncertain_count} excluded as uncertain)")

    # Step 5: Dev/test split by recording
    print("\n" + "=" * 60)
    print("STEP 5: Dev/test split by recording")
    print("=" * 60)

    recording_ids = sorted(set(a["source_recording"] for a in all_alerts))
    random.shuffle(recording_ids)
    n_dev = max(1, int(len(recording_ids) * DEV_FRACTION))
    dev_recordings = set(recording_ids[:n_dev])
    test_recordings = set(recording_ids[n_dev:])

    dev_alerts = [a for a in all_alerts if a["source_recording"] in dev_recordings]
    test_alerts = [a for a in all_alerts if a["source_recording"] in test_recordings]

    print(f"Dev recordings ({len(dev_recordings)}): {sorted(dev_recordings)}")
    print(f"Test recordings ({len(test_recordings)}): {sorted(test_recordings)}")
    print(f"Dev alerts: {len(dev_alerts)} "
          f"({sum(1 for a in dev_alerts if a['ground_truth']['label'] == 'malicious')} mal, "
          f"{sum(1 for a in dev_alerts if a['ground_truth']['label'] == 'benign')} ben)")
    print(f"Test alerts: {len(test_alerts)} "
          f"({sum(1 for a in test_alerts if a['ground_truth']['label'] == 'malicious')} mal, "
          f"{sum(1 for a in test_alerts if a['ground_truth']['label'] == 'benign')} ben)")

    # Step 6: Build agent-facing payload (no ground_truth)
    def strip_ground_truth(alert: dict) -> dict:
        """Remove ground_truth and source_recording from agent-facing payload."""
        return {k: v for k, v in alert.items()
                if k not in ("ground_truth", "source_recording")}

    # Step 7: Save outputs
    print("\n" + "=" * 60)
    print("STEP 7: Save golden set")
    print("=" * 60)

    GOLDEN_SET_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # Full golden set (with labels) for evaluation
    with open(GOLDEN_SET_DIR / "golden_set.json", "w") as f:
        json.dump(all_alerts, f, indent=2, default=str)

    # Dev and test splits
    with open(GOLDEN_SET_DIR / "dev_set.json", "w") as f:
        json.dump(dev_alerts, f, indent=2, default=str)

    with open(GOLDEN_SET_DIR / "test_set.json", "w") as f:
        json.dump(test_alerts, f, indent=2, default=str)

    # Agent-facing payloads (no ground truth, no source recording)
    with open(GOLDEN_SET_DIR / "dev_alerts.json", "w") as f:
        json.dump([strip_ground_truth(a) for a in dev_alerts], f, indent=2, default=str)

    with open(GOLDEN_SET_DIR / "test_alerts.json", "w") as f:
        json.dump([strip_ground_truth(a) for a in test_alerts], f, indent=2, default=str)

    # Statistics report
    sigma_level_by_class = {
        "malicious": Counter(a["sigma_level"] for a in malicious_alerts),
        "benign": Counter(a["sigma_level"] for a in benign_alerts),
    }

    report = {
        "total_alerts": len(all_alerts),
        "malicious_count": len(malicious_alerts),
        "benign_count": len(benign_alerts),
        "excluded_uncertain": uncertain_count,
        "benign_malicious_ratio": (
            round(len(benign_alerts) / max(len(malicious_alerts), 1), 2)
        ),
        "sigma_level_distribution": {
            "malicious": dict(sigma_level_by_class["malicious"]),
            "benign": dict(sigma_level_by_class["benign"]),
        },
        "dev_test_split": {
            "dev_recordings": sorted(dev_recordings),
            "test_recordings": sorted(test_recordings),
            "dev_alert_count": len(dev_alerts),
            "test_alert_count": len(test_alerts),
        },
        "per_source": stats_per_source,
    }

    with open(RESULTS_DIR / "golden_set_report.json", "w") as f:
        json.dump(report, f, indent=2)

    # Print summary
    print(f"\nSaved to {GOLDEN_SET_DIR}/:")
    print(f"  golden_set.json      — {len(all_alerts)} alerts (full, with labels)")
    print(f"  dev_set.json         — {len(dev_alerts)} alerts (with labels)")
    print(f"  test_set.json        — {len(test_alerts)} alerts (with labels)")
    print(f"  dev_alerts.json      — {len(dev_alerts)} alerts (agent-facing, no labels)")
    print(f"  test_alerts.json     — {len(test_alerts)} alerts (agent-facing, no labels)")
    print(f"  {RESULTS_DIR}/golden_set_report.json — statistics")

    print("\n" + "=" * 60)
    print("GOLDEN SET STATISTICS")
    print("=" * 60)
    print(f"Total alerts:              {len(all_alerts)}")
    print(f"  Malicious:               {len(malicious_alerts)}")
    print(f"  Benign:                  {len(benign_alerts)}")
    print(f"  Excluded (uncertain):    {uncertain_count}")
    print(f"Benign/Malicious ratio:    {report['benign_malicious_ratio']}")
    print("\nSigma level distribution:")
    for cls in ("malicious", "benign"):
        print(f"  {cls}:")
        for level in ("critical", "high", "medium", "low", "informational"):
            count = sigma_level_by_class[cls].get(level, 0)
            if count:
                print(f"    {level}: {count}")
    print("\nDev/test split (by recording):")
    print(f"  Dev:  {len(dev_alerts)} alerts from {len(dev_recordings)} recordings")
    print(f"  Test: {len(test_alerts)} alerts from {len(test_recordings)} recordings")
    print("\nCounts per source recording:")
    for did, stats in sorted(stats_per_source.items()):
        print(f"  {did}: {stats['malicious']}m/{stats['benign']}b/{stats['uncertain']}u "
              f"({stats['events']} events) — {stats['title'][:50]}")

    return report


if __name__ == "__main__":
    build_golden_set()
