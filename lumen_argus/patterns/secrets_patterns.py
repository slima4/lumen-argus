"""Built-in secret detection patterns (30+ compiled regexes)."""

import re
from typing import NamedTuple


class SecretPattern(NamedTuple):
    name: str
    pattern: "re.Pattern[str]"
    severity: str       # "critical" | "high" | "warning"
    needs_entropy: bool  # True = only flag if entropy exceeds threshold


# All patterns compiled at import time for <50ms scan target.
SECRETS_PATTERNS = (
    # --- Cloud Provider Keys ---
    SecretPattern(
        "aws_access_key",
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "critical", False,
    ),
    SecretPattern(
        "aws_secret_key",
        re.compile(r"(?i)(?:aws[_\s]*secret[_\s]*(?:access[_\s]*)?key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        "critical", False,
    ),
    SecretPattern(
        "google_api_key",
        re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
        "critical", False,
    ),
    SecretPattern(
        "gcp_service_account",
        re.compile(r'"type"\s*:\s*"service_account"'),
        "critical", False,
    ),
    SecretPattern(
        "azure_subscription_key",
        re.compile(r"(?i)(?:azure|subscription)[_\s]*key\s*[:=]\s*['\"][0-9a-f]{32}['\"]"),
        "high", False,
    ),

    # --- AI Provider Keys ---
    SecretPattern(
        "anthropic_api_key",
        re.compile(r"sk-ant-[a-zA-Z0-9\-_]{20,}"),
        "critical", False,
    ),
    SecretPattern(
        "openai_api_key",
        re.compile(r"sk-[a-zA-Z0-9]{20,}"),
        "critical", False,
    ),

    # --- Version Control & CI ---
    SecretPattern(
        "github_token",
        re.compile(r"gh[psor]_[A-Za-z0-9_]{36,}"),
        "critical", False,
    ),
    SecretPattern(
        "github_fine_grained_pat",
        re.compile(r"github_pat_[A-Za-z0-9_]{22,}"),
        "critical", False,
    ),
    SecretPattern(
        "gitlab_token",
        re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"),
        "critical", False,
    ),
    SecretPattern(
        "npm_token",
        re.compile(r"npm_[A-Za-z0-9]{36,}"),
        "critical", False,
    ),
    SecretPattern(
        "pypi_token",
        re.compile(r"pypi-[A-Za-z0-9\-_]{50,}"),
        "critical", False,
    ),

    # --- Cryptographic Material ---
    SecretPattern(
        "private_key_pem",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "critical", False,
    ),
    SecretPattern(
        "ssh_private_key",
        re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
        "critical", False,
    ),

    # --- Tokens & Sessions ---
    SecretPattern(
        "jwt_token",
        re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+"),
        "high", False,
    ),
    SecretPattern(
        "slack_token",
        re.compile(r"xox[bprs]-[0-9a-zA-Z\-]{10,}"),
        "critical", False,
    ),
    SecretPattern(
        "slack_webhook",
        re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+"),
        "high", False,
    ),
    SecretPattern(
        "discord_webhook",
        re.compile(r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+"),
        "high", False,
    ),

    # --- Payment ---
    SecretPattern(
        "stripe_secret_key",
        re.compile(r"[sr]k_(?:test|live)_[0-9a-zA-Z]{24,}"),
        "critical", False,
    ),
    SecretPattern(
        "stripe_webhook_secret",
        re.compile(r"whsec_[A-Za-z0-9]{24,}"),
        "critical", False,
    ),

    # --- Communication ---
    SecretPattern(
        "twilio_api_key",
        re.compile(r"SK[0-9a-fA-F]{32}"),
        "high", False,
    ),
    SecretPattern(
        "sendgrid_api_key",
        re.compile(r"SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{22,}"),
        "critical", False,
    ),
    SecretPattern(
        "mailgun_api_key",
        re.compile(r"key-[0-9a-zA-Z]{32}"),
        "high", False,
    ),

    # --- Infrastructure ---
    SecretPattern(
        "heroku_api_key",
        re.compile(r"(?i)heroku\s*[_\s]*api[_\s]*key\s*[:=]\s*['\"]?[0-9a-f\-]{36}['\"]?"),
        "critical", False,
    ),
    SecretPattern(
        "docker_hub_pat",
        re.compile(r"dckr_pat_[A-Za-z0-9\-_]{20,}"),
        "critical", False,
    ),
    SecretPattern(
        "terraform_cloud_token",
        re.compile(r"(?i)(?:terraform|tfe)[_\s]*token\s*[:=]\s*['\"][A-Za-z0-9.]{14,}['\"]"),
        "high", True,
    ),
    SecretPattern(
        "vault_token",
        re.compile(r"(?:hvs|s)\.[A-Za-z0-9]{24,}"),
        "critical", False,
    ),
    SecretPattern(
        "datadog_api_key",
        re.compile(r"(?i)(?:datadog|dd)[_\s]*(?:api[_\s]*)?key\s*[:=]\s*['\"]?[0-9a-f]{32}['\"]?"),
        "high", False,
    ),
    SecretPattern(
        "pagerduty_key",
        re.compile(r"(?i)pagerduty[_\s]*(?:api[_\s]*)?key\s*[:=]\s*['\"][A-Za-z0-9+/=]{20,}['\"]"),
        "high", True,
    ),

    # --- Database URLs ---
    SecretPattern(
        "database_url",
        re.compile(r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s'\"]+@[^\s'\"]+"),
        "critical", False,
    ),

    # --- Generic Patterns (entropy-gated) ---
    SecretPattern(
        "generic_password",
        re.compile(r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{8,})['\"]"),
        "high", True,
    ),
    SecretPattern(
        "generic_api_key",
        re.compile(r"(?i)(?:api[_\-]?key|apikey|secret[_\-]?key)\s*[:=]\s*['\"]([^'\"]{16,})['\"]"),
        "high", True,
    ),
    SecretPattern(
        "generic_secret",
        re.compile(r"(?i)(?:secret|token|credential)\s*[:=]\s*['\"]([^'\"]{16,})['\"]"),
        "high", True,
    ),
    SecretPattern(
        "basic_auth_url",
        re.compile(r"https?://[^:\s]+:[^@\s]+@[^\s]+"),
        "high", False,
    ),
    SecretPattern(
        "env_file_assignment",
        re.compile(r"(?i)^(?:export\s+)?(?:SECRET|TOKEN|API_KEY|PASSWORD|PRIVATE_KEY)[A-Z_]*\s*=\s*['\"]?[^\s'\"]{8,}['\"]?", re.MULTILINE),
        "warning", True,
    ),
)

# Keywords that indicate proximity to a potential secret (for entropy sweep).
SECRET_PROXIMITY_KEYWORDS = frozenset({
    "key", "secret", "token", "password", "passwd", "pwd",
    "credential", "auth", "private", "api_key", "apikey",
    "access_key", "secret_key", "bearer", "authorization",
})
