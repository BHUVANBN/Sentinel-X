"""
SENTINEL-X Unit Tests
Tests for each layer: normalizer, detection, correlation, explainability, response, API.
"""
import asyncio
import json
import uuid
import pytest
from datetime import datetime, timezone

from normalizer.schema import RawEvent, NormalizedEvent
from normalizer.normalizer import Normalizer
from detection.rule_loader import load_all_rules, DetectionRule
from detection.engine import DetectionEngine, CandidateAlert, is_internal_ip, is_external_ip
from correlation.engine import CorrelationEngine, CorrelatedAlert
from explainability.mitre_mapper import MitreMapper


# ─── Normalizer Tests ───────────────────────────────────

class TestNormalizer:
    def setup_method(self):
        self.normalizer = Normalizer()

    def test_linux_auth_failure(self):
        raw = RawEvent(
            source='linux_auth',
            event_type='login_failure',
            raw={'MESSAGE': 'Failed password for invalid user admin from 10.0.0.55 port 22345 ssh2'},
            timestamp='2025-01-01T00:00:00Z'
        )
        result = self.normalizer.normalize(raw)
        assert result is not None
        assert result.event_type == 'login_failure'
        assert result.category == 'authentication'
        assert result.outcome == 'failure'
        assert result.source_ip == '10.0.0.55'
        assert result.user == 'admin'
        assert result.platform == 'linux'

    def test_linux_auth_success(self):
        raw = RawEvent(
            source='linux_auth',
            event_type='login_success',
            raw={'MESSAGE': 'Accepted publickey for root from 192.168.1.100 port 50000 ssh2'},
            timestamp='2025-01-01T00:00:00Z'
        )
        result = self.normalizer.normalize(raw)
        assert result.event_type == 'login_success'
        assert result.outcome == 'success'
        assert result.source_ip == '192.168.1.100'

    def test_windows_login_failure(self):
        raw = RawEvent(
            source='windows_security_log',
            event_type='login_failure',
            raw={'event_id': 4625, 'data': ['', '', '', '', '', 'admin', '', '', '', '',
                                             '', '', '', '', '', '', '', '', '', '10.0.0.55']},
            timestamp='2025-01-01T00:00:00Z'
        )
        result = self.normalizer.normalize(raw)
        assert result.event_type == 'login_failure'
        assert result.platform == 'windows'
        assert result.outcome == 'failure'

    def test_process_event(self):
        raw = RawEvent(
            source='psutil_process',
            event_type='process_spawn',
            raw={
                'pid': 1234,
                'ppid': 1,
                'name': 'python3',
                'username': 'root',
                'exe': '/usr/bin/python3',
                'cmdline': 'python3 script.py',
                'platform': 'linux',
            },
            timestamp='2025-01-01T00:00:00Z'
        )
        result = self.normalizer.normalize(raw)
        assert result.event_type == 'process_spawn'
        assert result.category == 'process'
        assert result.pid == 1234
        assert result.process_name == 'python3'

    def test_network_event(self):
        raw = RawEvent(
            source='psutil_network',
            event_type='network_connect',
            raw={
                'local_ip': '192.168.1.10',
                'local_port': 50000,
                'remote_ip': '8.8.8.8',
                'remote_port': 443,
                'pid': 5678,
                'process_name': 'curl',
                'protocol': 'tcp',
                'platform': 'linux',
            },
            timestamp='2025-01-01T00:00:00Z'
        )
        result = self.normalizer.normalize(raw)
        assert result.event_type == 'network_connect'
        assert result.category == 'network'
        assert result.dest_ip == '8.8.8.8'
        assert result.dest_port == 443

    def test_unknown_source(self):
        raw = RawEvent(
            source='unknown_source',
            event_type='test',
            raw={},
            timestamp='2025-01-01T00:00:00Z'
        )
        result = self.normalizer.normalize(raw)
        assert result is None


# ─── Detection Engine Tests ─────────────────────────────

class TestDetectionEngine:
    def setup_method(self):
        self.rules = load_all_rules('detection/rules')
        self.engine = DetectionEngine(self.rules)
        self.normalizer = Normalizer()

    def _make_login_failure(self, source_ip: str = '10.0.0.55',
                             user: str = 'admin') -> NormalizedEvent:
        return NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            platform='linux',
            hostname='test-host',
            event_type='login_failure',
            category='authentication',
            action='attempt',
            outcome='failure',
            user=user,
            source_ip=source_ip,
            raw_source='linux_auth',
            raw_payload={},
        )

    def test_brute_force_detection(self):
        """BF-001: 10 failed logins from same IP should trigger."""
        alerts = []
        for i in range(12):
            result = self.engine.evaluate(self._make_login_failure())
            alerts.extend(result)

        assert len(alerts) >= 1
        alert = alerts[0]
        assert alert.rule.id == 'BF-001'
        assert alert.rule.severity == 'high'

    def test_below_threshold_no_alert(self):
        """Below threshold should not trigger."""
        alerts = []
        for i in range(5):  # Below 10 threshold
            result = self.engine.evaluate(self._make_login_failure())
            alerts.extend(result)
        assert len(alerts) == 0

    def test_password_spray_detection(self):
        """PS-001: Failed logins to 5+ distinct users from same IP."""
        alerts = []
        users = ['admin', 'root', 'user1', 'user2', 'user3', 'user4', 'user5']
        for user in users:
            result = self.engine.evaluate(
                self._make_login_failure(source_ip='10.0.0.77', user=user)
            )
            alerts.extend(result)

        # Should detect password spray
        spray_alerts = [a for a in alerts if a.rule.id == 'PS-001']
        assert len(spray_alerts) >= 1


# ─── IP Classification Tests ────────────────────────────

class TestIPClassification:
    def test_internal_ips(self):
        assert is_internal_ip('192.168.1.1') is True
        assert is_internal_ip('10.0.0.1') is True
        assert is_internal_ip('172.16.0.1') is True
        assert is_internal_ip('127.0.0.1') is True

    def test_external_ips(self):
        assert is_external_ip('8.8.8.8') is True
        assert is_external_ip('185.142.236.34') is True
        assert is_external_ip('1.1.1.1') is True

    def test_invalid_ip(self):
        assert is_internal_ip('') is False
        assert is_internal_ip('not-an-ip') is False


# ─── Correlation Engine Tests ────────────────────────────

class TestCorrelationEngine:
    def setup_method(self):
        self.engine = CorrelationEngine()

    def test_single_alert_passthrough(self):
        """Single alert should pass through as uncorrelated."""
        rules = load_all_rules('detection/rules')
        bf_rule = [r for r in rules if r.id == 'BF-001'][0]

        candidate = CandidateAlert(
            rule=bf_rule,
            evidence=[],
            source_ip='10.0.0.55',
            event_count=15,
            time_window_seconds=60,
        )
        result = self.engine.feed(candidate)
        assert isinstance(result, CorrelatedAlert)
        assert result.is_correlated is False

    def test_correlation_stats(self):
        stats = self.engine.get_stats()
        assert 'pending_candidates' in stats
        assert 'correlation_rules' in stats


# ─── MITRE Mapper Tests ─────────────────────────────────

class TestMitreMapper:
    def setup_method(self):
        self.mapper = MitreMapper()

    def test_known_technique(self):
        result = self.mapper.lookup('T1110')
        assert result['name'] == 'Brute Force'
        assert result['tactic'] == 'Credential Access'

    def test_unknown_technique(self):
        result = self.mapper.lookup('T9999')
        assert result['name'] == 'Unknown'

    def test_all_builtin_techniques(self):
        techniques = ['T1110', 'T1021', 'T1041', 'T1071', 'T1046', 'T1548', 'T1059', 'T1486']
        for tid in techniques:
            result = self.mapper.lookup(tid)
            assert result['name'] != 'Unknown', f"Missing technique: {tid}"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
