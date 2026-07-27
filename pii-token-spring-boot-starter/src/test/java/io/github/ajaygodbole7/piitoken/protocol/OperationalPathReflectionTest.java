package io.github.ajaygodbole7.piitoken.protocol;

import io.github.ajaygodbole7.piitoken.runtime.GeneratedPiiModel;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class OperationalPathReflectionTest {

    @Test
    void writeAndQueryPathsHaveNoReflectionBytecodeReferences() throws IOException {
        for (Class<?> type : List.of(
                PiiWriteInterceptor.class,
                GeneratedPiiJpaOperations.class,
                P1N1TokenEngine.class,
                GeneratedPiiModel.class)) {
            String constantPool = classBytes(type);
            assertThat(constantPool)
                    .as(type.getName())
                    .doesNotContain("java/lang/reflect")
                    .doesNotContain("getDeclaredField")
                    .doesNotContain("getDeclaredFields")
                    .doesNotContain("setAccessible");
        }
    }

    private static String classBytes(Class<?> type) throws IOException {
        String resource = "/" + type.getName().replace('.', '/') + ".class";
        try (InputStream input = type.getResourceAsStream(resource)) {
            assertThat(input).as(resource).isNotNull();
            return new String(input.readAllBytes(), StandardCharsets.ISO_8859_1);
        }
    }
}
