#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/pii-token-compatibility.XXXXXX")"
MAVEN_WORK="$WORK/maven-consumer"

cleanup() {
    rm -rf "$WORK"
}
trap cleanup EXIT HUP INT TERM

fail() {
    echo "compatibility gate failed: $*" >&2
    exit 1
}

contains() {
    local file="$1"
    local text="$2"
    grep -Fq "$text" "$file" || fail "$file does not contain $text"
}

prepare_maven_fixture() {
    mkdir -p "$MAVEN_WORK"
    cp "$ROOT/compatibility/maven-consumer/pom.xml" "$MAVEN_WORK/pom.xml"
    cp -R "$ROOT/compatibility/maven-consumer/src" "$MAVEN_WORK/src"
}

run_maven_fixture() {
    local generated="$MAVEN_WORK/target/generated-sources/annotations"
    local resources="$MAVEN_WORK/target/classes"
    local metadata="$generated/compat/fixture/CustomerPiiMetadata.java"
    local fragment="$generated/compat/fixture/CustomerPiiRepositoryFragment.java"
    local manifest="$resources/META-INF/pii/descriptor-manifest.txt"
    local marker="$resources/META-INF/pii/processor-marker.txt"
    local migration="$resources/META-INF/pii/owner-migration-template.sql"
    local ssn_migration="$resources/META-INF/pii/migrations/fields/fixture.customer.ssn.sql"

    "$ROOT/mvnw" -q -f "$MAVEN_WORK/pom.xml" clean test
    contains "$marker" "p1-jsr269-v1"
    contains "$metadata" "PanAccess"
    contains "$fragment" "existsBySsn"
    contains "$manifest" "fixture.customer.ssn"
    contains "$migration" \
        "fixture.customer.ssn -> META-INF/pii/migrations/fields/fixture.customer.ssn.sql"
    contains "$migration" "UPDATE pii_security.pii_policy_registry"
    contains "$ssn_migration" "CREATE INDEX <index_fixture_customer_ssn_token>"
}

scan_dependencies_and_api() {
    local starter_jar="$ROOT/pii-token-spring-boot-starter/target/pii-token-spring-boot-starter-0.1.0-SNAPSHOT.jar"
    local vault_jar="$ROOT/pii-token-provider-vault/target/pii-token-provider-vault-0.1.0-SNAPSHOT.jar"
    local kms_jar="$ROOT/pii-token-provider-kms/target/pii-token-provider-kms-0.1.0-SNAPSHOT.jar"
    local dependencies="$WORK/runtime-dependencies.txt"
    local vault_dependencies="$WORK/vault-runtime-dependencies.txt"
    local kms_dependencies="$WORK/kms-runtime-dependencies.txt"
    local jar_entries="$WORK/starter-jar.txt"
    local vault_jar_entries="$WORK/vault-jar.txt"
    local kms_jar_entries="$WORK/kms-jar.txt"
    local public_api="$WORK/public-api.txt"

    "$ROOT/mvnw" -q -pl pii-token-spring-boot-starter \
        dependency:tree -Dscope=runtime -DoutputFile="$dependencies"
    if grep -Eiq \
        'com\.azure|software\.amazon\.awssdk|com\.google\.cloud|testcontainers|projectlombok' \
        "$dependencies"; then
        fail "production dependency tree contains a prohibited SDK or test dependency"
    fi

    "$ROOT/mvnw" -q -pl pii-token-provider-vault \
        dependency:tree -Dscope=runtime -DoutputFile="$vault_dependencies"
    if grep -Eiq \
        'com\.azure|software\.amazon\.awssdk|com\.google\.cloud|spring-vault|testcontainers|projectlombok' \
        "$vault_dependencies"; then
        fail "Vault provider contains a prohibited cloud SDK or test dependency"
    fi

    "$ROOT/mvnw" -q -pl pii-token-provider-kms \
        dependency:tree -Dscope=runtime -DoutputFile="$kms_dependencies"
    if grep -Eiq \
        'com\.azure|com\.google\.cloud|spring-vault|testcontainers|projectlombok' \
        "$kms_dependencies"; then
        fail "KMS provider contains a prohibited cloud SDK or test dependency"
    fi

    jar tf "$starter_jar" > "$jar_entries"
    if grep -Eq \
        'TestMacProvider|AcceptanceTokenMacProvider|ProtocolTestFixture|testcontainers|lombok' \
        "$jar_entries"; then
        fail "production starter jar contains test/provider fixture material"
    fi
    jar tf "$vault_jar" > "$vault_jar_entries"
    if grep -Eq \
        'VaultDevFixture|VaultTransitTokenMacProviderTest|testcontainers|test-only-root-token' \
        "$vault_jar_entries"; then
        fail "production Vault provider jar contains test fixture material"
    fi
    jar tf "$kms_jar" > "$kms_jar_entries"
    if grep -Eq \
        'KmsTokenMacProviderTest|KmsTokenMacProviderIT|StubKmsClient|testcontainers|localstack' \
        "$kms_jar_entries"; then
        fail "production KMS provider jar contains test fixture material"
    fi

    : > "$public_api"
    scan_public_api "$starter_jar" "$jar_entries" "$public_api"
    scan_public_api "$vault_jar" "$vault_jar_entries" "$public_api"
    scan_public_api "$kms_jar" "$kms_jar_entries" "$public_api"

    if grep -Eq \
        ' (decrypt|recover|protect|tokenize|rawToken|searchTokens)\(' \
        "$public_api"; then
        fail "production public API exposes a forbidden recovery/raw-token method"
    fi
}

scan_public_api() {
    local artifact="$1"
    local entries="$2"
    local output="$3"
    while IFS= read -r entry; do
        case "$entry" in
            *'$'*|module-info.class)
                continue
                ;;
        esac
        local class_name="${entry%.class}"
        class_name="${class_name//\//.}"
        local declaration
        declaration="$(javap -classpath "$artifact" -public "$class_name" 2>/dev/null)"
        if grep -Eq '^public (final )?(class|interface|enum|record) ' \
                <<< "$declaration"; then
            printf '%s\n' "$declaration" >> "$output"
        fi
    done < <(grep '\.class$' "$entries")
}

"$ROOT/mvnw" -q -DskipTests install
"$ROOT/mvnw" -q -pl pii-token-spring-boot-starter \
    -Dtest=GoldenVectorTest test
prepare_maven_fixture
run_maven_fixture
scan_dependencies_and_api

echo "Compatibility gate passed: one clean Maven/Lombok consumer build,"
echo "Vault rotation + PostgreSQL tokenization, Java vectors, Vault/KMS API"
echo "scans, and dependency hygiene."
