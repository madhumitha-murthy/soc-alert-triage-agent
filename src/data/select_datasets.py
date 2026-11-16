"""Select diverse OTRF datasets for golden set construction."""

import json
from pathlib import Path

METADATA_PATH = Path("data/raw/metadata/all_metadata.json")

# Hand-picked 20 recordings for tactic/technique diversity (max 3 per sub-technique).
# Each entry: (dataset_id, short_reason)
SELECTED_IDS = [
    # TA0002 Execution
    "SDWIN-201102041306",  # PowerShell HTTP Listener (T1059.001)
    "SDWIN-190518182022",  # Empire VBS Execution (T1059.005)
    "SDWIN-191027223020",  # Covenant InstallUtil (T1218.004)
    # TA0003 Persistence
    "SDWIN-190319023812",  # Empire Registry Run Keys (T1547.001)
    "SDWIN-200921175806",  # Empire Elevated Scheduled Tasks (T1053.005)
    "SDWIN-201019224718",  # Logon Scripts UserInitMprLogonScript (T1037.001)
    # TA0004 Privilege Escalation
    "SDWIN-200904032946",  # Invoke BypassUAC FodHelper (T1548.002)
    "SDWIN-201021204544",  # Service Modification Fax (T1543.003)
    # TA0005 Defense Evasion
    "SDWIN-201022002145",  # HH CHM Execution (T1218.001)
    "SDWIN-201022022144",  # Mshta Javascript GetObject (T1218.005)
    "SDWIN-200721232741",  # Empire Regsvr32 (T1218.010)
    "SDWIN-201017061100",  # WMIC Remote XSL Jscript (T1220)
    # TA0006 Credential Access
    "SDWIN-190518202151",  # Empire Mimikatz LogonPasswords (T1003.001)
    "SDWIN-190625103712",  # Empire Mimikatz SAM Extract (T1003.002)
    "SDWIN-190301174830",  # Empire DCSync (T1003.006)
    "SDWIN-201018195009",  # Lsass Memory Dump via Comsvcs (T1003.001)
    # TA0007 Discovery
    "SDWIN-190319020147",  # Empire Net Local Admins Group (T1069.001)
    "SDWIN-201102163918",  # Seatbelt Group User Discovery (T1012)
    # TA0008 Lateral Movement
    "SDWIN-190518210125",  # Empire Invoke SMBExec (T1021.002)
    "SDWIN-200916232559",  # Mimikatz Netlogon Zerologon (T1210)
]


def load_metadata() -> list[dict]:
    with open(METADATA_PATH) as f:
        return json.load(f)


def get_selected_datasets() -> list[dict]:
    """Return metadata dicts for the selected recordings."""
    all_meta = load_metadata()
    by_id = {m["id"]: m for m in all_meta}
    selected = []
    for sid in SELECTED_IDS:
        if sid in by_id:
            selected.append(by_id[sid])
        else:
            print(f"WARNING: {sid} not found in metadata")
    return selected


def print_selection_summary(datasets: list[dict]) -> None:
    tactics_seen = set()
    techniques_seen = set()
    for m in datasets:
        for am in m.get("attack_mappings", []):
            tech = am.get("technique", "?")
            sub = am.get("sub-technique") or am.get("sub_technique")
            full = f"{tech}.{sub}" if sub else tech
            techniques_seen.add(full)
            for tac in am.get("tactics", []):
                tactics_seen.add(tac)
    print(f"Selected {len(datasets)} recordings")
    print(f"Unique tactics: {len(tactics_seen)} — {sorted(tactics_seen)}")
    print(f"Unique techniques: {len(techniques_seen)} — {sorted(techniques_seen)}")


if __name__ == "__main__":
    ds = get_selected_datasets()
    print_selection_summary(ds)
