"""Tests for the INV-006 secret scrubbing pipeline."""

import json

from src.scrubber import scrub, scrub_entry


class TestSecretPatterns:
    """Test that all known secret patterns are properly redacted."""

    def test_openai_key(self):
        text = "Using key sk-abc123def456ghi789jkl012mno345"
        result = scrub(text)
        assert "sk-abc123" not in result
        assert "[REDACTED]" in result

    def test_stripe_live_key(self):
        text = "Stripe key: sk_live_abc123def456ghi789jkl"
        result = scrub(text)
        assert "sk_live_" not in result
        assert "[REDACTED]" in result

    def test_stripe_test_key(self):
        text = "Test key: sk_test_abc123def456ghi789jkl"
        result = scrub(text)
        assert "sk_test_" not in result
        assert "[REDACTED]" in result

    def test_github_token(self):
        text = "Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk"
        result = scrub(text)
        assert "ghp_" not in result
        assert "[REDACTED]" in result

    def test_slack_token(self):
        text = "Slack: xoxb-123456789-abcdefghij"
        result = scrub(text)
        assert "xoxb-" not in result
        assert "[REDACTED]" in result

    def test_bearer_token(self):
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature"
        result = scrub(text)
        assert "Bearer [REDACTED]" in result
        assert "eyJ" not in result

    def test_jwt(self):
        text = "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        result = scrub(text)
        assert "eyJ" not in result
        assert "[REDACTED]" in result

    def test_connection_string_postgres(self):
        text = "DATABASE_URL=postgres://user:password@host:5432/dbname"
        result = scrub(text)
        assert "postgres://" not in result
        assert "[REDACTED]" in result

    def test_connection_string_redis(self):
        text = "REDIS_URL=redis://default:secret@redis:6379/0"
        result = scrub(text)
        assert "redis://" not in result
        assert "[REDACTED]" in result

    def test_aws_access_key(self):
        text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        result = scrub(text)
        assert "AKIAIOSFODNN7EXAMPLE" not in result

    def test_password_assignment(self):
        text = "password=my_super_secret_password123"
        result = scrub(text)
        assert "my_super_secret" not in result

    def test_private_key_header(self):
        text = "-----BEGIN RSA PRIVATE KEY-----"
        result = scrub(text)
        assert "PRIVATE KEY" not in result

    def test_api_key_assignment(self):
        text = "api_key=abc123def456ghi789jkl012mno"
        result = scrub(text)
        assert "abc123def456" not in result

    def test_generic_secret(self):
        text = "secret=abc123def456ghi789jkl012mno"
        result = scrub(text)
        assert "abc123def456" not in result


class TestNoFalsePositives:
    """Ensure normal log messages are not scrubbed."""

    def test_normal_message(self):
        text = "Request processed in 42ms for user 12345"
        assert scrub(text) == text

    def test_short_values_not_scrubbed(self):
        text = "api_key=short"
        assert scrub(text) == text

    def test_info_log(self):
        text = "Server started on port 8210"
        assert scrub(text) == text


class TestEinbrochUpstreamRedaction:
    """Test that entries with logging_strategy 'redacted' or 'partial' skip scrubbing."""

    def test_skip_redacted_entry(self):
        raw = json.dumps({
            "event": "dlp_scan_complete",
            "logging_strategy": "redacted",
            "payload_hash": "sha256:abc",
        })
        # Even with a secret-like pattern in message, it should NOT be scrubbed
        text = "Bearer eyJhbGciOiJIUzI1NiJ9.something.sig"
        result = scrub(text, raw=raw)
        assert result == text  # Unchanged

    def test_skip_partial_entry(self):
        raw = json.dumps({
            "event": "firewall_check",
            "logging_strategy": "partial",
        })
        text = "sk-abc123def456ghi789jkl012mno345"
        result = scrub(text, raw=raw)
        assert result == text  # Unchanged

    def test_scrub_full_strategy(self):
        raw = json.dumps({
            "event": "normal_log",
            "logging_strategy": "full",
        })
        text = "sk-abc123def456ghi789jkl012mno345"
        result = scrub(text, raw=raw)
        assert "[REDACTED]" in result

    def test_scrub_no_strategy(self):
        raw = json.dumps({"event": "normal_log"})
        text = "sk-abc123def456ghi789jkl012mno345"
        result = scrub(text, raw=raw)
        assert "[REDACTED]" in result


class TestScrubEntry:
    """Test the scrub_entry function that processes full normalized entries."""

    def test_scrubs_message_and_raw(self):
        entry = {
            "service": "dispatcher",
            "level": "info",
            "timestamp": "2025-02-21T10:00:00+00:00",
            "trace_id": None,
            "message": "Bearer eyJtoken.payload.signature_long_enough",
            "raw": '{"event":"test","token":"Bearer eyJtoken.payload.signature_long_enough"}',
        }
        result = scrub_entry(entry)
        assert "eyJtoken" not in result["message"]
        assert "eyJtoken" not in result["raw"]

    def test_skips_einbroch_redacted(self):
        entry = {
            "service": "einbroch",
            "level": "info",
            "timestamp": "2025-02-21T10:00:00+00:00",
            "trace_id": None,
            "message": "sk-abc123def456ghi789jkl012mno345",
            "raw": json.dumps({"logging_strategy": "redacted", "event": "test"}),
        }
        result = scrub_entry(entry)
        assert result["message"] == "sk-abc123def456ghi789jkl012mno345"
