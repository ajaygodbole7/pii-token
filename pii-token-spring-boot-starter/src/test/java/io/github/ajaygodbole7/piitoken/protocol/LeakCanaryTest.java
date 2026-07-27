package io.github.ajaygodbole7.piitoken.protocol;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.github.ajaygodbole7.piitoken.annotation.Kind;
import io.github.ajaygodbole7.piitoken.annotation.Mask;
import io.github.ajaygodbole7.piitoken.descriptor.PiiFieldDescriptor;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.HexFormat;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

class LeakCanaryTest {

    private static final String LOG_CONTROL = "pii-log-capture-positive-control";
    private static final String THROWABLE_CONTROL =
            "pii-throwable-capture-positive-control";
    private static final String SSN_PRESENTED = "923-45-6710";
    private static final String SSN_NORMALIZED = "923456710";
    private static final String PAN_PRESENTED = "4111 1111 1111 1111";
    private static final String PAN_NORMALIZED = "4111111111111111";

    @Test
    void libraryLogsAndThrowableGraphsExcludeProtectedCanaries() throws Exception {
        P1N1TokenEngine engine = new P1N1TokenEngine(
                new DigestFixtureProvider(),
                bytes -> java.util.Arrays.fill(bytes, (byte) 0x5a));
        TokenContext ssn = context("canary.customer.ssn", Kind.SSN, true);
        TokenContext pan = context("canary.customer.pan", Kind.PAN, false);

        Logger libraryLogger = (Logger) LoggerFactory.getLogger(
                "io.github.ajaygodbole7.piitoken");
        Level priorLevel = libraryLogger.getLevel();
        ListAppender<ILoggingEvent> capture = new ListAppender<>();
        capture.start();
        libraryLogger.addAppender(capture);
        libraryLogger.setLevel(Level.INFO);
        try {
            libraryLogger.info(LOG_CONTROL);
            assertThat(logText(capture)).contains(LOG_CONTROL);
            capture.list.clear();

            StagedProtection ssnOutput = engine.protect(ssn, SSN_PRESENTED);
            StagedProtection panOutput = engine.protect(pan, PAN_PRESENTED);
            List<String> canaries = canaries(ssn, pan, ssnOutput, panOutput);
            Throwable searchableFailure = catchThrowable(() -> engine.verify(
                    ssn,
                    SSN_PRESENTED,
                    "not-a-token-" + SSN_NORMALIZED));
            Throwable matchOnlyFailure = catchThrowable(() -> engine.verify(
                    pan,
                    PAN_PRESENTED + "x",
                    panOutput.token()));

            String logs = logText(capture);
            assertThat(logs).isEmpty();
            assertNoCanary(logs, canaries);

            String throwableControl = throwableGraph(
                    new IllegalStateException(THROWABLE_CONTROL));
            assertThat(throwableControl).contains(THROWABLE_CONTROL);
            assertNoCanary(throwableGraph(searchableFailure), canaries);
            assertNoCanary(throwableGraph(matchOnlyFailure), canaries);
        }
        finally {
            libraryLogger.setLevel(priorLevel);
            libraryLogger.detachAppender(capture);
            capture.stop();
        }
    }

    private static TokenContext context(
            String fieldId,
            Kind kind,
            boolean searchable) {
        return new TokenContext(
                "canary.bank",
                new PiiFieldDescriptor(
                        fieldId,
                        kind,
                        searchable,
                        Mask.LAST4,
                        "canary.Customer",
                        kind == Kind.SSN ? "ssn" : "pan"),
                "k1",
                List.of("k1"));
    }

    private static List<String> canaries(
            TokenContext ssn,
            TokenContext pan,
            StagedProtection ssnOutput,
            StagedProtection panOutput) {
        return List.of(
                SSN_PRESENTED,
                SSN_NORMALIZED,
                PAN_PRESENTED,
                PAN_NORMALIZED,
                ssnOutput.token(),
                panOutput.token(),
                ssnOutput.last4(),
                panOutput.last4(),
                digestHex(ssn, SSN_PRESENTED),
                digestHex(pan, PAN_PRESENTED),
                panOutput.token().split("\\.")[3],
                panOutput.token().split("\\.")[4],
                ssnOutput.token().split("\\.")[3]);
    }

    private static String digestHex(TokenContext context, String presented) {
        NormalizedValue normalized = N1Normalizer.normalize(
                context.descriptor().kind(),
                presented);
        byte[] domain = ProtocolBytes.domain(
                context.applicationNamespace(),
                context.descriptor());
        byte[] salt = context.descriptor().searchable()
                ? null
                : new byte[ProtocolBytes.SALT_BYTES];
        if (salt != null) {
            java.util.Arrays.fill(salt, (byte) 0x5a);
        }
        return HexFormat.of().formatHex(ProtocolBytes.sha256(
                ProtocolBytes.message(domain, normalized.ascii(), salt)));
    }

    private static String logText(ListAppender<ILoggingEvent> capture) {
        return capture.list.stream()
                .map(ILoggingEvent::getFormattedMessage)
                .reduce("", (left, right) -> left + "\n" + right);
    }

    private static String throwableGraph(Throwable root) {
        StringBuilder output = new StringBuilder();
        Set<Throwable> seen = java.util.Collections.newSetFromMap(
                new IdentityHashMap<>());
        ArrayDeque<Throwable> pending = new ArrayDeque<>();
        pending.add(root);
        while (!pending.isEmpty()) {
            Throwable current = pending.removeFirst();
            if (!seen.add(current)) {
                continue;
            }
            output.append(current.getClass().getName()).append('\n')
                    .append(current.getMessage()).append('\n')
                    .append(current).append('\n');
            for (StackTraceElement element : current.getStackTrace()) {
                output.append(element).append('\n');
            }
            if (current.getCause() != null) {
                pending.addLast(current.getCause());
            }
            pending.addAll(List.of(current.getSuppressed()));
        }
        return output.toString();
    }

    private static void assertNoCanary(String sink, List<String> canaries) {
        assertThat(canaries)
                .allSatisfy(canary -> assertThat(sink).doesNotContain(canary));
    }

    private static final class DigestFixtureProvider implements TestMacProvider {

        @Override
        public String currentVersion() {
            return "k1";
        }

        @Override
        public Set<String> liveVersions() {
            return Set.of("k1");
        }

        @Override
        public byte[] macDigest(String version, byte[] digest) {
            try {
                return MessageDigest.getInstance("SHA-256")
                        .digest((version + HexFormat.of().formatHex(digest))
                                .getBytes(StandardCharsets.US_ASCII));
            }
            catch (Exception exception) {
                throw new AssertionError(exception);
            }
        }
    }
}
