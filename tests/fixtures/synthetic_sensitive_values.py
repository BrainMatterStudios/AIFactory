"""Nonfunctional synthetic values used only to test security detectors.

These values deliberately resemble sensitive public-boundary shapes. They do
not authenticate to any service and contain no private project information.
The publication policy approves this exact file blob, Git mode, license,
provenance, and explicit rule set; any byte change invalidates that approval.
"""

AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
GITHUB_TOKEN = "ghp_" + ("A" * 36)
GITHUB_GENERIC_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123"
LLM_PROVIDER_KEY = "sk-or-v1-0123456789abcdef0123456789abcdef"
ANTHROPIC_KEY = "sk-ant-abcdefghijklmnopqrstuvwxyz123"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w"
AUTHORIZATION_BEARER = "Authorization: Bearer BBBBBBBBBBBBBBBBBBBBBBBB"
BEARER_VALUE = "Bearer abcdef0123456789ABCDEF"
AUTHORIZATION_HEADER = "Authorization: topsecret0123456789abcd"
SLACK_TOKEN = "xoxb-cccccccccccccccccccccccc"
PASSWORD_ASSIGNMENT = 'password = "hunter2isnotgreat"'
REDACT_PASSWORD_ASSIGNMENT = "PASSWORD=hunter2hunter2hunter2"
UTF16_PASSWORD_ASSIGNMENT = 'password = "correcthorsebattery"\n'
SYMLINK_PASSWORD_ASSIGNMENT = 'DATABASE_PASSWORD="hunter2seven99"'
QUOTED_CREDENTIAL_ASSIGNMENTS = (
    'STRIPE_SECRET_KEY = "sk_' + "live_" + ("A" * 24) + '"',
    'DATABASE_PASSWORD = "Pr0dPassw0rd"',
    'db_password = "correcthorsebattery"',
    '{"password": "hunter2seven"}',
    'openai_api_key = "abcdefghij1234567890"',
    'password := "hunter2seven"',
)
AWS_QUOTED_SECRET_ASSIGNMENT = (
    'AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMIK7MDENGbPxRfiCYKEY"'
)
OPENAI_ASSIGNMENT = "OPENAI_API_KEY = 'OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO'"
OPENROUTER_ASSIGNMENT = "OPENROUTER_API_KEY=sk-or-v1-0123456789abcdef0123456789abcdef"
CREDENTIAL_DSN = "postgresql://user:s3cretpw@db.internal:5432/app"
TRACE_DSN = "postgres://user:secret@db.example.com:5432/app"
PRIVATE_KEY_HEADER = "-----BEGIN RSA PRIVATE KEY-----"
PRIVATE_HOSTNAME = "database.service.internal"
PRIVATE_HOSTNAME_BOUNDARY_CASES = (
    "database.service.internal",
    "database.internal:5432",
    "https://database.internal/path",
    "database.internal.example",
)
INTERNAL_URL = "https://10.0.0.1/admin"
PRIVATE_URL_172 = "http://172.20.1.2/path"
PRIVATE_URL_192 = "http://192.168.1.2/path"
LINK_LOCAL_URL = "http://169.254.1.2/path"
LOCALHOST_URL = "http://localhost:8080/path"
PRIVATE_HOST_IP = "10.1.2.3"
CLOUD_ARN = "arn:aws:iam::123456789012:role/example"
ACCOUNT_ID = "123456789012"
PRIVATE_ABSOLUTE_PATH = "/Users/example/Private/project"
PRIVATE_WINDOWS_ABSOLUTE_PATH = "C:\\Users\\example\\Private\\project"
CONFIG_APPROVAL_SECRET_REPOSITORY = (
    "https://operator:SECRET-MUST-NOT-PRINT@github.com/acme/widgets.git"
)
CONFIG_APPROVAL_NONDEFAULT_REPOSITORY = (
    "https://operator:SUCCESS-MARKER@git.example.test:8443/acme/widgets.git"
)
CONFIG_ORIGIN_NONDEFAULT_REPOSITORY = (
    "https://operator:SUCCESS-ORIGIN@git.example.test:8443/acme/widgets.git"
)
CONFIG_MALFORMED_REPOSITORY = "https://operator:SECRET-NO-ECHO@/malformed.git"
CONFIG_PLACEHOLDER_CREDENTIAL_REPOSITORY = (
    "https://operator:SECRET-PLACEHOLDER@GitHub.COM:443/YOUR-ORG/YOUR-REPO.git"
)
CONFIG_INVALID_REPOSITORY_AUTHORITIES = (
    (
        "https://operator:LEAK-NFKC-COLON@example.test：443/acme/widgets.git",
        "operator:LEAK-NFKC-COLON@example.test：443",
        "LEAK-NFKC-COLON",
    ),
    (
        "https://operator:LEAK-NFKC-AT＠example.test/acme/widgets.git",
        "operator:LEAK-NFKC-AT＠example.test",
        "LEAK-NFKC-AT",
    ),
    (
        "https://operator:LEAK-PORT@example.test:not-a-port/acme/widgets.git",
        "operator:LEAK-PORT@example.test:not-a-port",
        "LEAK-PORT",
    ),
    (
        "https://operator:LEAK-RANGE@example.test:70000/acme/widgets.git",
        "operator:LEAK-RANGE@example.test:70000",
        "LEAK-RANGE",
    ),
    (
        "https://operator:LEAK-IPV6@[::1/acme/widgets.git",
        "operator:LEAK-IPV6@[::1",
        "LEAK-IPV6",
    ),
)
CONFIG_UNSAFE_REPOSITORY_IDENTITIES = (
    "operator:SECRET-SCP@github.com:acme/widgets.git",
    "git@github.com:acme/SECRET-NEWLINE\nwidgets.git",
    "git@github.com:acme/SECRET-CR\rwidgets.git",
    "git@github.com:acme/SECRET-TAB\twidgets.git",
    "git@github.com:acme/SECRET-TRAILING-NEWLINE.git\n",
    "git@github.com:acme/SECRET-TRAILING-CR.git\r",
    "git@github.com:acme/SECRET-TRAILING-TAB.git\t",
    "git@github.com:acme/SECRET-ANSI\x1b[31mwidgets.git",
    "git@github.com:acme/SECRET-NUL\0widgets.git",
    "git@github.com:acme/SECRET-BIDI\u202ewidgets.git",
    "git@operator:SECRET-MULTI-AT@github.com:acme/widgets.git",
    "git@github.com:acme/SECRET-MULTI:COLON/widgets.git",
    "https://operator:SECRET-URL@other@github.com/acme/widgets.git",
    "https://operator:SECRET%0A@example.test/acme/widgets.git",
    "https://example.test/acme/SECRET%0Awidgets.git",
    "https://operator:SECRET-QUERY@example.test/acme/widgets.git?token=SECRET",
    "https://operator:SECRET-FRAGMENT@example.test/acme/widgets.git#SECRET",
    "acme/SECRET-DOUBLE//widgets",
    "acme/../SECRET-DOT-SEGMENT",
    "git@git.example.test:/acme/SECRET-SCP-ABSOLUTE.git",
    "/acme/SECRET-ABSOLUTE-NONURL",
    "https://operator:SECRET-EMPTY-PORT@git.example.test:/acme/widgets.git",
    "https://operator:SECRET-EMPTY-QUERY@git.example.test/acme/widgets.git?",
    "https://operator:SECRET-EMPTY-FRAGMENT@git.example.test/acme/widgets.git#",
)
