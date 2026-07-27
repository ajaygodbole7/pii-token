CREATE SCHEMA pii_security;

CREATE TABLE pii_security.pii_policy_registry (
    id                     integer PRIMARY KEY DEFAULT 1,
    application_namespace  text NOT NULL,
    protocol_profile       text NOT NULL,
    provider_profile       text NOT NULL,
    key_set_id             text NOT NULL,
    descriptor_manifest    text NOT NULL,
    descriptor_fingerprint text NOT NULL,
    CONSTRAINT pii_policy_registry_single_row CHECK (id = 1),
    CONSTRAINT pii_policy_registry_namespace CHECK (
        application_namespace ~ '^[a-z0-9.-]{3,64}$'
    ),
    CONSTRAINT pii_policy_registry_protocol CHECK (protocol_profile = 'p1/n1'),
    CONSTRAINT pii_policy_registry_provider CHECK (
        provider_profile = 'HMAC_SHA256_PREHASH_V1'
    ),
    CONSTRAINT pii_policy_registry_key_set CHECK (
        length(key_set_id) BETWEEN 1 AND 128
        AND key_set_id !~ '[[:cntrl:]]'
    ),
    CONSTRAINT pii_policy_registry_fingerprint CHECK (
        descriptor_fingerprint ~ '^[0-9a-f]{64}$'
    )
);

CREATE TABLE pii_security.pii_key_version_registry (
    provider_id     text NOT NULL,
    key_set_id      text NOT NULL,
    logical_version text NOT NULL,
    opaque_ref      text NOT NULL,
    state           text NOT NULL CHECK (state IN ('CURRENT', 'READ_ONLY', 'RETIRED')),
    PRIMARY KEY (provider_id, key_set_id, logical_version),
    CONSTRAINT pii_key_version_provider_id CHECK (
        length(provider_id) BETWEEN 1 AND 128
        AND provider_id !~ '[[:cntrl:]]'
    ),
    CONSTRAINT pii_key_version_key_set CHECK (
        length(key_set_id) BETWEEN 1 AND 128
        AND key_set_id !~ '[[:cntrl:]]'
    ),
    CONSTRAINT pii_key_version_logical_version CHECK (
        logical_version ~ '^[a-z0-9][a-z0-9_-]{0,31}$'
    ),
    CONSTRAINT pii_key_version_opaque_ref CHECK (
        length(opaque_ref) BETWEEN 1 AND 512
        AND opaque_ref !~ '[[:cntrl:]]'
    )
);

CREATE UNIQUE INDEX pii_key_version_one_current
    ON pii_security.pii_key_version_registry (provider_id, key_set_id)
    WHERE state = 'CURRENT';

INSERT INTO pii_security.pii_policy_registry (
    id,
    application_namespace,
    protocol_profile,
    provider_profile,
    key_set_id,
    descriptor_manifest,
    descriptor_fingerprint
) VALUES (
    1,
    'consumer.app',
    'p1/n1',
    'HMAC_SHA256_PREHASH_V1',
    'consumer-vault-key-set',
    E'fixture.customer.pan|PAN|false|NONE|compat.fixture.Customer|pan\nfixture.customer.ssn|SSN|true|LAST4|compat.fixture.Customer|ssn',
    'd418f1c86ebed8c72f65768df364ed071184ecd01191190d43eff4c8173df8be'
);

INSERT INTO pii_security.pii_key_version_registry (
    provider_id,
    key_set_id,
    logical_version,
    opaque_ref,
    state
) VALUES
    ('hashicorp-vault-transit', 'consumer-vault-key-set', 'k1',
        'vault-transit:transit:pii-token:v1', 'READ_ONLY'),
    ('hashicorp-vault-transit', 'consumer-vault-key-set', 'k2',
        'vault-transit:transit:pii-token:v2', 'CURRENT');
