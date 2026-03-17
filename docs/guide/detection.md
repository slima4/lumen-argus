# Detection

lumen-argus ships with three built-in detectors that run sequentially on every
request body: **secrets**, **PII**, and **proprietary content**. All regex
patterns are compiled at import time to meet the <50ms scanning target.

## Secrets Detector

The secrets detector combines 34+ compiled regex patterns with Shannon entropy
analysis to catch credentials, tokens, and cryptographic material.

### Cloud Provider Keys

| Pattern Name | Example Match | Severity |
|---|---|---|
| `aws_access_key` | `AKIA...` (20 chars) | critical |
| `aws_secret_key` | `aws_secret_key = "..."` (40 chars) | critical |
| `google_api_key` | `AIza...` (39 chars) | critical |
| `gcp_service_account` | `"type": "service_account"` | critical |
| `azure_subscription_key` | `azure_key = "..."` (32 hex chars) | high |

### AI Provider Keys

| Pattern Name | Example Match | Severity |
|---|---|---|
| `anthropic_api_key` | `sk-ant-...` | critical |
| `openai_api_key` | `sk-...` (20+ chars, entropy-gated) | critical |

### Version Control and CI Tokens

| Pattern Name | Example Match | Severity |
|---|---|---|
| `github_token` | `ghp_...`, `ghs_...`, `gho_...`, `ghr_...` (36+ chars) | critical |
| `github_fine_grained_pat` | `github_pat_...` (22+ chars) | critical |
| `gitlab_token` | `glpat-...` (20+ chars) | critical |
| `npm_token` | `npm_...` (36+ chars) | critical |
| `pypi_token` | `pypi-...` (50+ chars) | critical |

### Cryptographic Material

| Pattern Name | Example Match | Severity |
|---|---|---|
| `private_key_pem` | `-----BEGIN RSA PRIVATE KEY-----` | critical |
| `ssh_private_key` | `-----BEGIN OPENSSH PRIVATE KEY-----` | critical |

### Tokens and Sessions

| Pattern Name | Example Match | Severity |
|---|---|---|
| `jwt_token` | `eyJ...eyJ...` (3-part base64) | high |
| `slack_token` | `xoxb-...`, `xoxp-...` | critical |
| `slack_webhook` | `https://hooks.slack.com/services/T.../B.../...` | high |
| `discord_webhook` | `https://discord.com/api/webhooks/...` | high |

### Payment

| Pattern Name | Example Match | Severity |
|---|---|---|
| `stripe_secret_key` | `sk_live_...`, `sk_test_...`, `rk_live_...` | critical |
| `stripe_webhook_secret` | `whsec_...` | critical |

### Communication Services

| Pattern Name | Example Match | Severity |
|---|---|---|
| `twilio_api_key` | `SK...` (32 hex chars) | high |
| `sendgrid_api_key` | `SG....` (two base64 segments) | critical |
| `mailgun_api_key` | `key-...` (32 chars) | high |

### Infrastructure

| Pattern Name | Example Match | Severity |
|---|---|---|
| `heroku_api_key` | `heroku_api_key = "..."` (UUID) | critical |
| `docker_hub_pat` | `dckr_pat_...` (20+ chars) | critical |
| `terraform_cloud_token` | `terraform_token = "..."` (entropy-gated) | high |
| `vault_token` | `hvs....` (24+ chars) | critical |
| `datadog_api_key` | `datadog_key = "..."` (32 hex chars) | high |
| `pagerduty_key` | `pagerduty_key = "..."` (entropy-gated) | high |

### Database URLs

| Pattern Name | Example Match | Severity |
|---|---|---|
| `database_url` | `postgres://user:pass@host/db`, `mongodb+srv://...` | critical |
| `basic_auth_url` | `https://user:pass@host` | high |

### Generic Patterns (Entropy-Gated)

These patterns require Shannon entropy >4.5 bits/char to avoid false positives
on placeholder values:

| Pattern Name | What It Matches | Severity |
|---|---|---|
| `generic_password` | `password = "..."` (8+ chars) | high |
| `generic_api_key` | `api_key = "..."` (16+ chars) | high |
| `generic_secret` | `secret = "..."` (16+ chars) | high |
| `env_file_assignment` | `export SECRET_KEY=...` | warning |

### Shannon Entropy Analysis

Beyond pattern matching, the secrets detector performs an entropy sweep on text
near secret-related keywords. This catches credentials that do not match any
specific pattern but have the statistical profile of a random secret.

```
Entropy threshold: 4.5 bits/char (configurable)
```

!!! info "Proximity keywords"
    The entropy sweep activates when text appears near keywords like `key`,
    `secret`, `token`, `password`, `credential`, `auth`, `private`, `api_key`,
    `access_key`, `bearer`, and `authorization`.

---

## PII Detector

The PII detector uses regex patterns with domain-specific validators to reduce
false positives. Every match is validated before producing a finding.

### Patterns

=== "Email"

    - **Pattern**: Standard email format
    - **Severity**: warning
    - **Validation**: None (regex match is sufficient)

=== "SSN"

    - **Pattern**: `NNN-NN-NNNN`
    - **Severity**: critical
    - **Validation**: Range validation rejects area `000`, `666`, and `900+`; rejects group `00` and serial `0000`

=== "Credit Card"

    - **Pattern**: 13-19 digit card numbers (with optional spaces/dashes)
    - **Severity**: critical
    - **Validation**: Luhn algorithm checksum

=== "Phone (US)"

    - **Pattern**: US phone numbers with optional `+1`, parentheses, dots, dashes
    - **Severity**: warning
    - **Validation**: None

=== "Phone (International)"

    - **Pattern**: `+N NNNN...` (country code + 4-14 digits)
    - **Severity**: info
    - **Validation**: None

=== "IP Address"

    - **Pattern**: `N.N.N.N` (dotted quad)
    - **Severity**: info
    - **Validation**: Excludes private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`), and link-local (`169.254.0.0/16`)

=== "IBAN"

    - **Pattern**: Two-letter country code + 2 check digits + up to 30 alphanumeric chars
    - **Severity**: warning
    - **Validation**: MOD-97 checksum (ISO 13616)

=== "Passport (US)"

    - **Pattern**: One uppercase letter followed by 8 digits
    - **Severity**: info
    - **Validation**: None

---

## Proprietary Content Detector

The proprietary detector catches two categories: **sensitive file types** being
sent to AI providers and **confidentiality keywords** in request content.

### File Pattern Blocklist

!!! danger "Critical severity"
    ```
    *.pem  *.key  *.p12  *.pfx  id_rsa*
    *.env  *.env.*  .npmrc  .pypirc
    credentials.json  service-account*.json  *secret*
    ```

!!! warning "Warning severity"
    ```
    *.sqlite  *.db  *.sql  *dump*
    ```

### Keyword Detection

Keywords are matched case-insensitively in the full request body text.

!!! danger "Critical keywords"
    `CONFIDENTIAL` `PROPRIETARY` `TRADE SECRET`
    `DO NOT DISTRIBUTE` `INTERNAL ONLY` `NDA REQUIRED`

!!! warning "Warning keywords"
    `DRAFT` `PRE-RELEASE` `UNRELEASED`

---

## Severity Levels

All findings carry one of four severity levels:

| Level | Meaning | Typical Action |
|---|---|---|
| **critical** | Active credentials, keys, or highly sensitive data | `block` |
| **high** | Probable secrets, passwords with high entropy | `block` or `alert` |
| **warning** | Possible PII, sensitive keywords, draft markers | `alert` |
| **info** | Low-confidence signals (international phone, public IP) | `log` |

---

## Finding Deduplication

When the same secret appears multiple times in a request (common with
autocomplete context), findings are collapsed into a single entry with a count.

```
lumen-argus: 3 finding(s) detected
  [CRITICAL] secrets: aws_access_key (x47)
  [WARNING]  pii: email (x3)
  [INFO]     pii: ip_address
```

Deduplication uses a composite key of `(detector, type, matched_value)`. The
count reflects how many times the identical value was found across all scanned
fields in the request.
