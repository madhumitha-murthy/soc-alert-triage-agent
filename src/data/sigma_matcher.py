"""Lightweight Sigma rule parser and matcher for JSON event logs.

Supports the subset of Sigma syntax used in common Windows detection rules:
- Field conditions with modifiers: |endswith, |startswith, |contains, |re, |all
- Value lists (OR within a field)
- Selection groups (AND across fields within a selection)
- Conditions: selection, selection1 and selection2, selection1 or selection2,
  1 of selection*, all of selection*, not selection, selection and not filter
"""

import fnmatch
import re
from pathlib import Path
from typing import Any

import yaml


def load_sigma_rule(path: Path) -> dict | None:
    """Parse a Sigma YAML rule file. Returns None if invalid."""
    try:
        with open(path) as f:
            docs = list(yaml.safe_load_all(f))
        if not docs:
            return None
        rule = docs[0]
        if not isinstance(rule, dict) or "detection" not in rule:
            return None
        return rule
    except Exception:
        return None


def _normalize_field(field: str) -> str:
    """Normalize event field names for case-insensitive matching."""
    return field.lower().strip()


def _get_event_value(event: dict, field: str) -> str | None:
    """Get a field value from an event, trying case-insensitive lookup."""
    # Try exact match first
    if field in event:
        return str(event[field]) if event[field] is not None else None
    # Case-insensitive
    lower_field = field.lower()
    for k, v in event.items():
        if k.lower() == lower_field:
            return str(v) if v is not None else None
    # Try nested EventData fields (common in Windows event logs)
    event_data = event.get("EventData") or event.get("eventdata") or {}
    if isinstance(event_data, dict):
        if field in event_data:
            return str(event_data[field]) if event_data[field] is not None else None
        for k, v in event_data.items():
            if k.lower() == lower_field:
                return str(v) if v is not None else None
    return None


def _match_value(event_val: str, pattern: Any, modifier: str = "") -> bool:
    """Check if an event value matches a Sigma value pattern with optional modifier."""
    if event_val is None:
        return False

    ev_lower = event_val.lower()

    if isinstance(pattern, bool):
        return ev_lower in ("true", "1") if pattern else ev_lower in ("false", "0", "")

    if isinstance(pattern, (int, float)):
        try:
            return float(event_val) == float(pattern)
        except ValueError:
            return str(pattern) in event_val

    pat = str(pattern)
    pat_lower = pat.lower()

    if modifier == "re":
        try:
            return bool(re.search(pat, event_val, re.IGNORECASE))
        except re.error:
            return False
    elif modifier == "endswith":
        return ev_lower.endswith(pat_lower)
    elif modifier == "startswith":
        return ev_lower.startswith(pat_lower)
    elif modifier == "contains":
        return pat_lower in ev_lower
    else:
        # Default: exact or wildcard match
        if "*" in pat or "?" in pat:
            return fnmatch.fnmatch(ev_lower, pat_lower)
        return ev_lower == pat_lower


def _match_selection(event: dict, selection: dict) -> bool:
    """Match a single Sigma selection block against an event.

    All field conditions must match (AND logic).
    Multiple values for a single field use OR logic (unless |all modifier).
    """
    if not isinstance(selection, dict):
        return False

    for field_expr, values in selection.items():
        # Parse field name and modifier
        parts = field_expr.split("|")
        field_name = parts[0]
        modifiers = parts[1:] if len(parts) > 1 else []

        use_all = "all" in modifiers
        # Get the actual matching modifier (endswith, startswith, etc.)
        match_mod = ""
        for mod in modifiers:
            if mod in ("endswith", "startswith", "contains", "re"):
                match_mod = mod
                break

        event_val = _get_event_value(event, field_name)

        # Normalize values to list
        if not isinstance(values, list):
            values = [values]

        if use_all:
            # All values must match
            if not all(_match_value(event_val, v, match_mod) for v in values):
                return False
        else:
            # At least one value must match (OR)
            if not any(_match_value(event_val, v, match_mod) for v in values):
                return False

    return True


def _evaluate_condition(event: dict, detection: dict) -> bool:
    """Evaluate the Sigma detection condition against an event."""
    condition = detection.get("condition", "")
    if not condition:
        return False

    # Build named selections (everything except 'condition' and 'timeframe')
    selections = {}
    for key, val in detection.items():
        if key not in ("condition", "timeframe"):
            selections[key] = val

    # Parse condition string
    cond = condition.strip()

    # Handle "1 of selection*" / "all of selection*" / "1 of them"
    match_1of = re.match(r"(\d+|all)\s+of\s+(\w+\*|them)", cond)
    if match_1of:
        quantifier = match_1of.group(1)
        target = match_1of.group(2)

        if target == "them":
            relevant = list(selections.values())
        else:
            prefix = target.rstrip("*")
            relevant = [v for k, v in selections.items() if k.startswith(prefix)]

        matches = sum(
            1 for sel in relevant
            if isinstance(sel, dict) and _match_selection(event, sel)
        )

        if quantifier == "all":
            return matches == len(relevant)
        return matches >= int(quantifier)

    # Handle "selection and not filter" patterns
    and_not_match = re.match(r"(\w+)\s+and\s+not\s+(\w+)", cond)
    if and_not_match:
        sel_name = and_not_match.group(1)
        filter_name = and_not_match.group(2)
        sel = selections.get(sel_name, {})
        filt = selections.get(filter_name, {})
        return _match_selection(event, sel) and not _match_selection(event, filt)

    # Handle "not selection"
    if cond.startswith("not "):
        sel_name = cond[4:].strip()
        sel = selections.get(sel_name, {})
        return not _match_selection(event, sel)

    # Handle "selection1 and selection2 [and selection3...]"
    if " and " in cond and " or " not in cond:
        parts = [p.strip() for p in cond.split(" and ")]
        return all(
            _match_selection(event, selections.get(p, {}))
            for p in parts
            if not p.startswith("not ")
        ) and all(
            not _match_selection(event, selections.get(p[4:].strip(), {}))
            for p in parts
            if p.startswith("not ")
        )

    # Handle "selection1 or selection2"
    if " or " in cond and " and " not in cond:
        parts = [p.strip() for p in cond.split(" or ")]
        return any(_match_selection(event, selections.get(p, {})) for p in parts)

    # Handle compound: (sel1 or sel2) and not filter
    compound = re.match(r"\((.+)\)\s+and\s+not\s+(\w+)", cond)
    if compound:
        inner = compound.group(1)
        filter_name = compound.group(2)
        filt = selections.get(filter_name, {})
        if _match_selection(event, filt):
            return False
        # Evaluate inner as OR
        inner_parts = [p.strip() for p in inner.split(" or ")]
        return any(_match_selection(event, selections.get(p, {})) for p in inner_parts)

    # Simple single selection
    sel = selections.get(cond, {})
    if isinstance(sel, dict):
        return _match_selection(event, sel)

    return False


def _extract_rule_event_ids(rule: dict) -> set[int] | None:
    """Extract EventID values from a rule's detection for pre-filtering.

    Returns None if rule doesn't filter on EventID (matches any event).
    """
    detection = rule.get("detection", {})
    event_ids = set()
    for key, val in detection.items():
        if key in ("condition", "timeframe"):
            continue
        if isinstance(val, dict):
            for field_expr, field_val in val.items():
                field_name = field_expr.split("|")[0]
                if field_name.lower() == "eventid":
                    if isinstance(field_val, list):
                        event_ids.update(int(v) for v in field_val if str(v).isdigit())
                    elif str(field_val).isdigit():
                        event_ids.add(int(field_val))
    return event_ids if event_ids else None


def match_rule(rule: dict, events: list[dict]) -> list[dict]:
    """Run a Sigma rule against events. Returns matching events."""
    detection = rule.get("detection", {})
    if not detection:
        return []

    matches = []
    for event in events:
        try:
            if _evaluate_condition(event, detection):
                matches.append(event)
        except Exception:
            continue
    return matches


def match_rules_optimized(
    rules: list[dict],
    events: list[dict],
    max_matches_per_rule: int = 5,
) -> list[tuple[dict, dict]]:
    """Match many rules against many events with EventID pre-filtering.

    Returns list of (rule, matched_event) tuples.
    """
    # Index events by EventID for fast lookup
    events_by_eid: dict[int, list[dict]] = {}
    events_no_eid: list[dict] = []
    for event in events:
        eid = event.get("EventID") or event.get("eventid")
        if eid is not None:
            try:
                eid_int = int(eid)
                events_by_eid.setdefault(eid_int, []).append(event)
            except (ValueError, TypeError):
                events_no_eid.append(event)
        else:
            events_no_eid.append(event)

    results = []
    for rule in rules:
        detection = rule.get("detection", {})
        if not detection:
            continue

        # Pre-filter: only check events with matching EventIDs
        rule_eids = _extract_rule_event_ids(rule)
        if rule_eids:
            candidate_events = []
            for eid in rule_eids:
                candidate_events.extend(events_by_eid.get(eid, []))
        else:
            # Rule doesn't filter on EventID — check all events
            candidate_events = events

        match_count = 0
        for event in candidate_events:
            if match_count >= max_matches_per_rule:
                break
            try:
                if _evaluate_condition(event, detection):
                    results.append((rule, event))
                    match_count += 1
            except Exception:
                continue

    return results


def load_sigma_rules_from_dir(sigma_dir: Path, max_rules: int = 5000) -> list[dict]:
    """Load all valid Sigma rules from a directory tree."""
    rules = []
    yaml_files = sorted(sigma_dir.rglob("*.yml"))
    for yf in yaml_files[:max_rules]:
        rule = load_sigma_rule(yf)
        if rule:
            rules.append(rule)
    return rules


def get_rule_attack_tags(rule: dict) -> list[str]:
    """Extract ATT&CK technique IDs from rule tags (e.g., 'attack.t1059.001')."""
    tags = rule.get("tags", [])
    techniques = []
    for tag in tags:
        if isinstance(tag, str) and tag.startswith("attack.t"):
            tech_id = tag.replace("attack.", "").upper().replace(".", ".", 1)
            # Normalize: T1059.001 format
            techniques.append(tech_id)
    return techniques


def get_rule_level(rule: dict) -> str:
    """Get the Sigma rule severity level."""
    return rule.get("level", "medium")
