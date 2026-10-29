CREATE TABLE threats (
    md5 TEXT PRIMARY KEY CHECK (md5 ~ '^[0-9a-f]{32}$'),
    name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 255),
    type TEXT NOT NULL CHECK (type IN ('trojan', 'virus', 'worm', 'ransomware', 'backdoor', 'spyware', 'adware', 'riskware', 'exploit', 'unknown')),
    platform TEXT NOT NULL CHECK (platform IN ('windows', 'linux', 'macos', 'android', 'ios', 'multi', 'unknown')),
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical', 'unknown')),
    status TEXT NOT NULL CHECK (status IN ('active', 'false_positive', 'revoked')),
    sha256 TEXT CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    file_size BIGINT CHECK (file_size >= 0),
    description TEXT CHECK (char_length(description) <= 2000),
    tags TEXT[] NOT NULL DEFAULT '{}',
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (cardinality(tags) <= 20),
    CHECK (last_seen >= first_seen)
);
