package io.github.ajaygodbole7.piitoken.protocol;

import io.github.ajaygodbole7.piitoken.descriptor.PiiFieldDescriptor;
import io.github.ajaygodbole7.piitoken.provider.TokenMacProvider;

import java.util.List;

/**
 * Test-only access to frozen protocol output for database acceptance fixtures.
 */
public final class ProtocolTestFixture {

    private ProtocolTestFixture() {
    }

    public static String searchableToken(
            String applicationNamespace,
            PiiFieldDescriptor descriptor,
            String logicalVersion,
            String value,
            TokenMacProvider provider) {
        var engine = new P1N1TokenEngine(provider, target -> {
            throw new AssertionError("Searchable token requested salt");
        });
        var context = new TokenContext(
                applicationNamespace,
                descriptor,
                logicalVersion,
                List.of(logicalVersion));
        return engine.protect(context, value).token();
    }
}
