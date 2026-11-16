"""Tests for the Sigma rule parser and matcher."""

from src.data.sigma_matcher import (
    _evaluate_condition,
    _extract_rule_event_ids,
    _get_event_value,
    _match_selection,
    _match_value,
    get_rule_attack_tags,
    get_rule_level,
    load_sigma_rule,
    match_rules_optimized,
)

# --- _match_value tests ---

class TestMatchValue:
    def test_exact_match(self):
        assert _match_value("svchost.exe", "svchost.exe")

    def test_exact_case_insensitive(self):
        assert _match_value("SvcHost.EXE", "svchost.exe")

    def test_exact_no_match(self):
        assert not _match_value("cmd.exe", "svchost.exe")

    def test_wildcard(self):
        assert _match_value("C:\\Windows\\System32\\cmd.exe", "*\\cmd.exe")

    def test_wildcard_no_match(self):
        assert not _match_value("C:\\tools\\evil.exe", "*\\cmd.exe")

    def test_endswith(self):
        assert _match_value("C:\\Windows\\cmd.exe", "cmd.exe", "endswith")

    def test_endswith_no_match(self):
        assert not _match_value("C:\\Windows\\cmd.exe", "powershell.exe", "endswith")

    def test_startswith(self):
        assert _match_value("C:\\Windows\\System32\\x", "c:\\windows", "startswith")

    def test_contains(self):
        assert _match_value("powershell -enc SGVsbG8=", "-enc", "contains")

    def test_contains_no_match(self):
        assert not _match_value("powershell -nop", "-enc", "contains")

    def test_re_modifier(self):
        assert _match_value("mimikatz.exe", r"mimi.*\.exe", "re")

    def test_re_no_match(self):
        assert not _match_value("notepad.exe", r"mimi.*\.exe", "re")

    def test_none_value(self):
        assert not _match_value(None, "anything")

    def test_int_pattern(self):
        assert _match_value("1", 1)

    def test_bool_true(self):
        assert _match_value("true", True)

    def test_bool_false(self):
        assert _match_value("false", False)


# --- _get_event_value tests ---

class TestGetEventValue:
    def test_direct_match(self):
        assert _get_event_value({"Image": "cmd.exe"}, "Image") == "cmd.exe"

    def test_case_insensitive(self):
        assert _get_event_value({"image": "cmd.exe"}, "Image") == "cmd.exe"

    def test_nested_eventdata(self):
        event = {"EventData": {"TargetFilename": "evil.dll"}}
        assert _get_event_value(event, "TargetFilename") == "evil.dll"

    def test_missing_field(self):
        assert _get_event_value({"Image": "x"}, "CommandLine") is None

    def test_none_value(self):
        assert _get_event_value({"Image": None}, "Image") is None


# --- _match_selection tests ---

class TestMatchSelection:
    def test_single_field_match(self):
        event = {"Image": "C:\\Windows\\cmd.exe"}
        sel = {"Image|endswith": "cmd.exe"}
        assert _match_selection(event, sel)

    def test_and_logic_all_match(self):
        event = {"Image": "cmd.exe", "User": "SYSTEM"}
        sel = {"Image": "cmd.exe", "User": "SYSTEM"}
        assert _match_selection(event, sel)

    def test_and_logic_partial_match(self):
        event = {"Image": "cmd.exe", "User": "john"}
        sel = {"Image": "cmd.exe", "User": "SYSTEM"}
        assert not _match_selection(event, sel)

    def test_or_values(self):
        event = {"Image": "powershell.exe"}
        sel = {"Image": ["cmd.exe", "powershell.exe", "wscript.exe"]}
        assert _match_selection(event, sel)

    def test_or_values_no_match(self):
        event = {"Image": "notepad.exe"}
        sel = {"Image": ["cmd.exe", "powershell.exe"]}
        assert not _match_selection(event, sel)

    def test_all_modifier(self):
        event = {"CommandLine": "powershell -enc -nop hidden"}
        sel = {"CommandLine|contains|all": ["-enc", "-nop"]}
        assert _match_selection(event, sel)

    def test_all_modifier_partial(self):
        event = {"CommandLine": "powershell -enc something"}
        sel = {"CommandLine|contains|all": ["-enc", "-nop"]}
        assert not _match_selection(event, sel)

    def test_non_dict_selection(self):
        assert not _match_selection({"x": 1}, "not a dict")


# --- _evaluate_condition tests ---

class TestEvaluateCondition:
    def _make_detection(self, selections, condition):
        d = dict(selections)
        d["condition"] = condition
        return d

    def test_simple_selection(self):
        event = {"Image": "cmd.exe"}
        det = self._make_detection(
            {"selection": {"Image": "cmd.exe"}}, "selection"
        )
        assert _evaluate_condition(event, det)

    def test_selection_no_match(self):
        event = {"Image": "notepad.exe"}
        det = self._make_detection(
            {"selection": {"Image": "cmd.exe"}}, "selection"
        )
        assert not _evaluate_condition(event, det)

    def test_and_condition(self):
        event = {"Image": "cmd.exe", "User": "SYSTEM"}
        det = self._make_detection({
            "selection1": {"Image": "cmd.exe"},
            "selection2": {"User": "SYSTEM"},
        }, "selection1 and selection2")
        assert _evaluate_condition(event, det)

    def test_and_condition_partial(self):
        event = {"Image": "cmd.exe", "User": "john"}
        det = self._make_detection({
            "selection1": {"Image": "cmd.exe"},
            "selection2": {"User": "SYSTEM"},
        }, "selection1 and selection2")
        assert not _evaluate_condition(event, det)

    def test_or_condition(self):
        event = {"Image": "powershell.exe"}
        det = self._make_detection({
            "selection1": {"Image": "cmd.exe"},
            "selection2": {"Image": "powershell.exe"},
        }, "selection1 or selection2")
        assert _evaluate_condition(event, det)

    def test_and_not_filter(self):
        event = {"Image": "cmd.exe", "User": "SYSTEM"}
        det = self._make_detection({
            "selection": {"Image": "cmd.exe"},
            "filter": {"User": "john"},
        }, "selection and not filter")
        assert _evaluate_condition(event, det)

    def test_and_not_filter_excluded(self):
        event = {"Image": "cmd.exe", "User": "john"}
        det = self._make_detection({
            "selection": {"Image": "cmd.exe"},
            "filter": {"User": "john"},
        }, "selection and not filter")
        assert not _evaluate_condition(event, det)

    def test_1_of_selection_star(self):
        event = {"Image": "powershell.exe"}
        det = self._make_detection({
            "selection_a": {"Image": "cmd.exe"},
            "selection_b": {"Image": "powershell.exe"},
        }, "1 of selection_*")
        assert _evaluate_condition(event, det)

    def test_all_of_them(self):
        event = {"Image": "cmd.exe", "User": "SYSTEM"}
        det = self._make_detection({
            "selection1": {"Image": "cmd.exe"},
            "selection2": {"User": "SYSTEM"},
        }, "all of them")
        assert _evaluate_condition(event, det)

    def test_all_of_them_partial(self):
        event = {"Image": "cmd.exe", "User": "john"}
        det = self._make_detection({
            "selection1": {"Image": "cmd.exe"},
            "selection2": {"User": "SYSTEM"},
        }, "all of them")
        assert not _evaluate_condition(event, det)

    def test_not_condition(self):
        event = {"Image": "notepad.exe"}
        det = self._make_detection(
            {"selection": {"Image": "cmd.exe"}}, "not selection"
        )
        assert _evaluate_condition(event, det)

    def test_empty_condition(self):
        assert not _evaluate_condition({}, {"condition": ""})


# --- _extract_rule_event_ids tests ---

class TestExtractRuleEventIds:
    def test_single_eventid(self):
        rule = {"detection": {"selection": {"EventID": 1}, "condition": "selection"}}
        assert _extract_rule_event_ids(rule) == {1}

    def test_multiple_eventids(self):
        rule = {"detection": {"selection": {"EventID": [1, 3, 7]}, "condition": "selection"}}
        assert _extract_rule_event_ids(rule) == {1, 3, 7}

    def test_no_eventid(self):
        rule = {"detection": {"selection": {"Image": "cmd.exe"}, "condition": "selection"}}
        assert _extract_rule_event_ids(rule) is None

    def test_empty_detection(self):
        assert _extract_rule_event_ids({"detection": {}}) is None


# --- match_rules_optimized tests ---

class TestMatchRulesOptimized:
    def test_eventid_prefiltering(self):
        rules = [{
            "detection": {
                "selection": {"EventID": 1, "Image|endswith": "cmd.exe"},
                "condition": "selection",
            }
        }]
        events = [
            {"EventID": 1, "Image": "C:\\Windows\\cmd.exe"},
            {"EventID": 5158, "Image": "C:\\Windows\\svchost.exe"},
        ]
        results = match_rules_optimized(rules, events)
        assert len(results) == 1
        assert results[0][1]["Image"] == "C:\\Windows\\cmd.exe"

    def test_max_matches_per_rule(self):
        rule = {"detection": {"selection": {"EventID": 1}, "condition": "selection"}}
        events = [{"EventID": 1, "idx": i} for i in range(20)]
        results = match_rules_optimized([rule], events, max_matches_per_rule=3)
        assert len(results) == 3

    def test_no_matches(self):
        rule = {"detection": {"selection": {"EventID": 9999}, "condition": "selection"}}
        events = [{"EventID": 1}]
        results = match_rules_optimized([rule], events)
        assert len(results) == 0


# --- load_sigma_rule tests ---

class TestLoadSigmaRule:
    def test_valid_rule(self, tmp_path):
        rule_yaml = """
title: Test Rule
detection:
    selection:
        Image|endswith: cmd.exe
    condition: selection
level: high
"""
        p = tmp_path / "test.yml"
        p.write_text(rule_yaml)
        rule = load_sigma_rule(p)
        assert rule is not None
        assert rule["title"] == "Test Rule"
        assert rule["level"] == "high"

    def test_invalid_yaml(self, tmp_path):
        p = tmp_path / "bad.yml"
        p.write_text("{{not yaml")
        assert load_sigma_rule(p) is None

    def test_no_detection(self, tmp_path):
        p = tmp_path / "nodet.yml"
        p.write_text("title: No Detection\nlevel: low\n")
        assert load_sigma_rule(p) is None


# --- Helper function tests ---

class TestHelpers:
    def test_get_rule_level(self):
        assert get_rule_level({"level": "critical"}) == "critical"
        assert get_rule_level({}) == "medium"

    def test_get_rule_attack_tags(self):
        rule = {"tags": ["attack.t1059.001", "attack.execution", "attack.t1003"]}
        tags = get_rule_attack_tags(rule)
        assert "T1059.001" in tags
        assert "T1003" in tags
        assert len(tags) == 2  # Only technique tags, not tactic

    def test_get_rule_attack_tags_empty(self):
        assert get_rule_attack_tags({}) == []
