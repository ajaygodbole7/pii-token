package io.github.ajaygodbole7.piitoken.kms;

import io.github.ajaygodbole7.piitoken.provider.ProviderFailureReason;
import io.github.ajaygodbole7.piitoken.provider.TokenMacException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.localstack.LocalStackContainer;
import org.testcontainers.utility.DockerImageName;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.retries.StandardRetryStrategy;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.AlgorithmSpec;
import software.amazon.awssdk.services.kms.model.CreateKeyRequest;
import software.amazon.awssdk.services.kms.model.ExpirationModelType;
import software.amazon.awssdk.services.kms.model.GenerateMacRequest;
import software.amazon.awssdk.services.kms.model.GetParametersForImportRequest;
import software.amazon.awssdk.services.kms.model.ImportKeyMaterialRequest;
import software.amazon.awssdk.services.kms.model.KeySpec;
import software.amazon.awssdk.services.kms.model.KeyUsageType;
import software.amazon.awssdk.services.kms.model.MacAlgorithmSpec;
import software.amazon.awssdk.services.kms.model.OriginType;
import software.amazon.awssdk.services.kms.model.WrappingKeySpec;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Wire-level compatibility tests against pinned LocalStack.
 *
 * <p>LocalStack exercises KMS request and response framing but does not enforce
 * AWS IAM. Authentication and authorization failure mapping therefore remains
 * unit-tested with real AWS SDK exception types and is not fabricated here.
 * AWS production behavior, quotas, latency, and HSM custody are outside this
 * emulator's fidelity boundary.
 */
@Testcontainers
class KmsTokenMacProviderIT {

    private static final String IMAGE = "localstack/localstack:4.14.0";
    private static final byte[] DIGEST = fixedDigest();
    private static final byte[] GOLDEN_KEY = HexFormat.of().parseHex(
            "000102030405060708090a0b0c0d0e0f"
                    + "101112131415161718191a1b1c1d1e1f");
    private static final byte[] GOLDEN_DIGEST = HexFormat.of().parseHex(
            "dac3b73b79e8543f66fff6cfe7710db3"
                    + "757ccc0c6350643919716d095bba1f83");
    private static final byte[] GOLDEN_MAC = HexFormat.of().parseHex(
            "18c182504e1b5c3b7107cb683152e9a8"
                    + "bdf1d4a38b7c7a4ca04b646251e82d77");

    @Container
    private static final LocalStackContainer LOCALSTACK =
            new LocalStackContainer(DockerImageName.parse(IMAGE))
                    .withServices("kms");

    private static KmsClient kms;
    private static String k1Arn;
    private static String k2Arn;

    @BeforeAll
    static void createKeys() {
        assertThat(System.getProperty("pii.kms.localstack.image"))
                .isEqualTo(IMAGE);
        kms = KmsClient.builder()
                .endpointOverride(LOCALSTACK.getEndpoint())
                .region(Region.of(LOCALSTACK.getRegion()))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(
                                LOCALSTACK.getAccessKey(),
                                LOCALSTACK.getSecretKey())))
                .overrideConfiguration(ClientOverrideConfiguration.builder()
                        .retryStrategy(StandardRetryStrategy.builder()
                                .maxAttempts(1)
                                .build())
                        .apiCallTimeout(Duration.ofSeconds(5))
                        .apiCallAttemptTimeout(Duration.ofSeconds(5))
                        .build())
                .build();
        k1Arn = createHmacKey(OriginType.AWS_KMS);
        k2Arn = createHmacKey(OriginType.AWS_KMS);
    }

    @AfterAll
    static void closeClient() {
        if (kms != null) {
            kms.close();
        }
    }

    @Test
    void isDeterministicDistinctAndPinnedAcrossNewWriteRollover() {
        byte[] k1Before;
        try (var provider = provider(
                Map.of("k1", k1Arn),
                "k1")) {
            k1Before = provider.macDigest("k1", DIGEST);
            assertThat(provider.macDigest("k1", DIGEST))
                    .containsExactly(k1Before);
        }

        try (var provider = provider(
                Map.of("k1", k1Arn, "k2", k2Arn),
                "k2")) {
            byte[] k1After = provider.macDigest("k1", DIGEST);
            byte[] k2First = provider.macDigest("k2", DIGEST);
            byte[] k2Second = provider.macDigest("k2", DIGEST);

            assertThat(k1After).containsExactly(k1Before);
            assertThat(k2First)
                    .hasSize(32)
                    .isNotEqualTo(k1Before);
            assertThat(k2Second).containsExactly(k2First);
        }
    }

    @Test
    void assertsTheRealResponseKeyArnAndFullMac() {
        var response = kms.generateMac(GenerateMacRequest.builder()
                .keyId(k2Arn)
                .macAlgorithm(MacAlgorithmSpec.HMAC_SHA_256)
                .message(SdkBytes.fromByteArray(DIGEST))
                .build());

        assertThat(response.keyId()).isEqualTo(k2Arn);
        assertThat(response.mac().asByteArray()).hasSize(32);

        try (var provider = provider(
                Map.of("k2", k2Arn),
                "k2")) {
            assertThat(provider.macDigest("k2", DIGEST))
                    .containsExactly(response.mac().asByteArray());
        }
    }

    @Test
    void rejectsMalformedAndUnknownInputAndMapsDisabledKeyContentFree() {
        try (var provider = provider(
                Map.of("k1", k1Arn),
                "k1")) {
            assertReason(
                    ProviderFailureReason.UNKNOWN_VERSION,
                    () -> provider.macDigest("k2", DIGEST));
            assertReason(
                    ProviderFailureReason.INVALID_INPUT,
                    () -> provider.macDigest("k1", new byte[31]));
        }

        String disabledArn = createHmacKey(OriginType.AWS_KMS);
        kms.disableKey(request -> request.keyId(disabledArn));
        try (var provider = provider(
                Map.of("k1", disabledArn),
                "k1")) {
            assertReason(
                    ProviderFailureReason.UNAVAILABLE,
                    () -> provider.macDigest("k1", DIGEST));
        }
    }

    @Test
    void reproducesThePublishedGoldenVectorWithImportedHmacMaterial() {
        String importedArn = createHmacKey(OriginType.EXTERNAL);
        importGoldenKey(importedArn);

        try (var provider = provider(
                Map.of("golden", importedArn),
                "golden")) {
            assertThat(provider.macDigest("golden", GOLDEN_DIGEST))
                    .containsExactly(GOLDEN_MAC);
        }
    }

    private static void importGoldenKey(String keyArn) {
        var parameters = kms.getParametersForImport(
                GetParametersForImportRequest.builder()
                        .keyId(keyArn)
                        .wrappingAlgorithm(AlgorithmSpec.RSAES_OAEP_SHA_256)
                        .wrappingKeySpec(WrappingKeySpec.RSA_2048)
                        .build());
        try {
            var publicKey = KeyFactory.getInstance("RSA").generatePublic(
                    new X509EncodedKeySpec(
                            parameters.publicKey().asByteArray()));
            Cipher cipher = Cipher.getInstance(
                    "RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(
                    Cipher.ENCRYPT_MODE,
                    publicKey,
                    new OAEPParameterSpec(
                            "SHA-256",
                            "MGF1",
                            MGF1ParameterSpec.SHA256,
                            PSource.PSpecified.DEFAULT));
            byte[] encrypted = cipher.doFinal(GOLDEN_KEY);
            kms.importKeyMaterial(ImportKeyMaterialRequest.builder()
                    .keyId(keyArn)
                    .importToken(parameters.importToken())
                    .encryptedKeyMaterial(SdkBytes.fromByteArray(encrypted))
                    .expirationModel(
                            ExpirationModelType.KEY_MATERIAL_DOES_NOT_EXPIRE)
                    .build());
        }
        catch (GeneralSecurityException failure) {
            throw new AssertionError("golden key wrapping failed");
        }
    }

    private static String createHmacKey(OriginType origin) {
        return kms.createKey(CreateKeyRequest.builder()
                        .description("test-only PII token HMAC key")
                        .keySpec(KeySpec.HMAC_256)
                        .keyUsage(KeyUsageType.GENERATE_VERIFY_MAC)
                        .origin(origin)
                        .build())
                .keyMetadata()
                .arn();
    }

    private static KmsTokenMacProvider provider(
            Map<String, String> keys,
            String current) {
        var properties = new KmsHmacProperties();
        properties.setRegion(LOCALSTACK.getRegion());
        properties.setKeySetId("localstack-integration-key-set");
        properties.setCurrentVersion(current);
        properties.setKeyArns(keys);
        properties.setTotalDeadline(Duration.ofSeconds(5));
        properties.setMaxAttempts(2);
        return new KmsTokenMacProvider(properties, kms);
    }

    private static byte[] fixedDigest() {
        byte[] digest = new byte[32];
        for (int index = 0; index < digest.length; index++) {
            digest[index] = (byte) (index + 1);
        }
        return digest;
    }

    private static void assertReason(
            ProviderFailureReason expected,
            Runnable operation) {
        assertThatThrownBy(operation::run)
                .isInstanceOfSatisfying(
                        TokenMacException.class,
                        failure -> assertThat(failure.reason())
                                .isEqualTo(expected))
                .hasMessage(expected.name())
                .hasNoCause();
    }
}
