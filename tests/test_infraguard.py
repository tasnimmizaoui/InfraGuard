"""
Unit tests for InfraGuard.
Run with: pytest tests/
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta

from infra_guard.config import Config
from infra_guard.utils import (
    is_date_older_than,
    create_finding,
    chunk_list,
    setup_logging
)


class TestConfig(unittest.TestCase):
    """Test configuration module."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = Config()
        self.assertEqual(config.aws_region, 'us-east-1')
        self.assertTrue(config.check_iam_unused_users)
        self.assertEqual(config.iam_unused_threshold_days, 90)
    
    def test_config_validation(self):
        """Test configuration validation."""
        config = Config()
        config.s3_bucket = None
        config.sns_topic_arn = None
        config.slack_webhook_url = None
        
        warnings = config.validate()
        self.assertGreater(len(warnings), 0)
        self.assertTrue(any('S3_BUCKET' in w for w in warnings))


class TestUtils(unittest.TestCase):
    """Test utility functions."""
    
    def test_is_date_older_than(self):
        """Test date comparison utility."""
        old_date = datetime.utcnow() - timedelta(days=100)
        recent_date = datetime.utcnow() - timedelta(days=10)
        
        self.assertTrue(is_date_older_than(old_date, 90))
        self.assertFalse(is_date_older_than(recent_date, 90))
    
    def test_create_finding(self):
        """Test finding creation."""
        finding = create_finding(
            category="IAM",
            severity="HIGH",
            description="Test finding",
            resource="test-resource",
            details={"key": "value"},
            recommendation="Fix it"
        )
        
        self.assertEqual(finding['category'], 'IAM')
        self.assertEqual(finding['severity'], 'HIGH')
        self.assertIn('timestamp', finding)
        self.assertEqual(finding['details']['key'], 'value')
    
    def test_chunk_list(self):
        """Test list chunking."""
        items = list(range(10))
        chunks = chunk_list(items, 3)
        
        self.assertEqual(len(chunks), 4)
        self.assertEqual(chunks[0], [0, 1, 2])
        self.assertEqual(chunks[-1], [9])


class TestSecurityChecker(unittest.TestCase):
    """Test security checker."""
    
    @patch('infra_guard.detection_rules.get_aws_client')
    def test_check_root_access_keys(self, mock_get_client):
        """Test root access key detection."""
        from infra_guard.detection_rules import SecurityChecker
        
        # Mock IAM client
        mock_iam = MagicMock()
        mock_iam.get_account_summary.return_value = {
            'SummaryMap': {
                'AccountAccessKeysPresent': 1
            }
        }
        mock_get_client.return_value = mock_iam
        
        config = Config()
        checker = SecurityChecker(config)
        findings = checker.check_iam_root_key_exists()
        
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['severity'], 'CRITICAL')
        self.assertIn('root', findings[0]['description'].lower())


class TestCloudTrailAnalyzer(unittest.TestCase):
    """Test CloudTrail analyzer."""
    
    def test_find_root_usage(self):
        """Test root account usage detection."""
        from infra_guard.log_ingestion import CloudTrailAnalyzer
        
        events = [
            {
                'eventTime': '2026-01-26T10:00:00Z',
                'eventName': 'ConsoleLogin',
                'userIdentity': {'type': 'Root'},
                'sourceIPAddress': '1.2.3.4',
                'userAgent': 'console.aws.amazon.com',
                'eventID': 'abc123'
            },
            {
                'eventTime': '2026-01-26T10:05:00Z',
                'eventName': 'ListBuckets',
                'userIdentity': {'type': 'IAMUser', 'userName': 'testuser'},
                'sourceIPAddress': '5.6.7.8',
                'eventID': 'def456'
            }
        ]
        
        analyzer = CloudTrailAnalyzer()
        root_events = analyzer.find_root_account_usage(events)
        
        self.assertEqual(len(root_events), 1)
        self.assertEqual(root_events[0]['event_name'], 'ConsoleLogin')


class TestVPCFlowLogIngestion(unittest.TestCase):
    """Test VPC Flow Log ingestion."""
    
    def test_parse_flow_log_record(self):
        """Test parsing VPC Flow Log record."""
        from infra_guard.log_ingestion import VPCFlowLogIngestion
        
        config = Config()
        ingestion = VPCFlowLogIngestion(config)
        
        # Sample VPC Flow Log line
        line = "2 123456789 eni-abc123 10.0.1.5 52.94.133.131 49152 443 6 10 5000 1234567890 1234567895 ACCEPT OK"
        
        record = ingestion.parse_flow_log_record(line)
        
        self.assertIsNotNone(record)
        self.assertEqual(record['src_addr'], '10.0.1.5')
        self.assertEqual(record['dst_port'], 443)
        self.assertEqual(record['action'], 'ACCEPT')
    
    def test_filter_rejected_traffic(self):
        """Test filtering rejected traffic."""
        from infra_guard.log_ingestion import VPCFlowLogIngestion
        
        config = Config()
        ingestion = VPCFlowLogIngestion(config)
        
        records = [
            {'action': 'ACCEPT', 'dst_port': 443},
            {'action': 'REJECT', 'dst_port': 22},
            {'action': 'REJECT', 'dst_port': 3306},
            {'action': 'ACCEPT', 'dst_port': 80}
        ]
        
        rejected = ingestion.filter_rejected_traffic(records)
        
        self.assertEqual(len(rejected), 2)
        self.assertTrue(all(r['action'] == 'REJECT' for r in rejected))


if __name__ == '__main__':
    unittest.main()
