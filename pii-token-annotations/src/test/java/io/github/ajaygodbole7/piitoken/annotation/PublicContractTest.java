package io.github.ajaygodbole7.piitoken.annotation;

import io.github.ajaygodbole7.piitoken.descriptor.PiiFieldDescriptor;
import org.junit.jupiter.api.Test;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

class PublicContractTest {

    @Test
    void annotationIsRuntimeVisibleOnFieldsOnly() {
        assertThat(PII.class.getAnnotation(Retention.class).value())
                .isEqualTo(RetentionPolicy.RUNTIME);
        assertThat(PII.class.getAnnotation(Target.class).value())
                .containsExactly(ElementType.FIELD);
    }

    @Test
    void safeAbsenceDefaultsDoNotAuthorizeLeakage() throws Exception {
        assertThat(PII.class.getDeclaredMethod("searchable").getDefaultValue())
                .isEqualTo(false);
        assertThat(PII.class.getDeclaredMethod("mask").getDefaultValue())
                .isEqualTo(Mask.NONE);
    }

    @Test
    void enumSurfaceContainsOnlyApprovedV1Choices() {
        assertThat(Kind.values()).containsExactly(Kind.SSN, Kind.PAN);
        assertThat(Mask.values()).containsExactly(Mask.NONE, Mask.LAST4);
    }

    @Test
    void publicSurfaceHasNoRecoveryVocabulary() {
        assertThat(Arrays.stream(PII.class.getDeclaredMethods())
                .map(method -> method.getName().toLowerCase()))
                .noneMatch(name -> name.contains("decrypt")
                        || name.contains("recover")
                        || name.contains("plaintext"));
    }

    @Test
    void descriptorPreservesAllSixManifestFields() {
        var descriptor = new PiiFieldDescriptor(
                "customer.ssn",
                Kind.SSN,
                true,
                Mask.LAST4,
                "bank.Customer",
                "ssn");

        assertThat(descriptor)
                .extracting(
                        PiiFieldDescriptor::id,
                        PiiFieldDescriptor::kind,
                        PiiFieldDescriptor::searchable,
                        PiiFieldDescriptor::mask,
                        PiiFieldDescriptor::entityClassName,
                        PiiFieldDescriptor::fieldName)
                .containsExactly(
                        "customer.ssn",
                        Kind.SSN,
                        true,
                        Mask.LAST4,
                        "bank.Customer",
                        "ssn");
    }
}
