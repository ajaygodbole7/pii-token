package io.github.ajaygodbole7.piitoken.runtime;

import io.github.ajaygodbole7.piitoken.descriptor.PiiDescriptorRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class GeneratedPiiModelTest {

    private static final String MARKER = "META-INF/pii/processor-marker.txt";
    private static final String SERVICES =
            "META-INF/services/" + PiiDescriptorRegistry.class.getName();

    @TempDir
    Path temporary;

    @Test
    void missingProcessorMarkerFailsClosed() {
        ClassLoader classLoader = resources(Map.of(
                MARKER, List.of(),
                SERVICES, List.of()));

        assertThatThrownBy(() -> GeneratedPiiModel.load(classLoader))
                .isInstanceOf(StartupValidationException.class)
                .hasMessage(StartupReason.GENERATED_OUTPUT_MISSING.name());
    }

    @Test
    void malformedProcessorMarkerFailsClosed() throws Exception {
        URL marker = resource("wrong-marker\n");
        ClassLoader classLoader = resources(Map.of(
                MARKER, List.of(marker),
                SERVICES, List.of()));

        assertThatThrownBy(() -> GeneratedPiiModel.load(classLoader))
                .isInstanceOf(StartupValidationException.class)
                .hasMessage(StartupReason.GENERATED_OUTPUT_INVALID.name());
    }

    @Test
    void validZeroPiiCompilationIsDistinctFromMissingProcessor() throws Exception {
        URL marker = resource(PiiDescriptorRegistry.PROCESSOR_MARKER + "\n");
        ClassLoader classLoader = resources(Map.of(
                MARKER, List.of(marker),
                SERVICES, List.of()));

        GeneratedPiiModel model = GeneratedPiiModel.load(classLoader);

        assertThat(model.fields()).isEmpty();
        assertThat(model.descriptors()).isEmpty();
    }

    private URL resource(String value) throws Exception {
        Path file = temporary.resolve("resource-" + System.nanoTime());
        Files.writeString(file, value);
        return file.toUri().toURL();
    }

    private static ClassLoader resources(Map<String, List<URL>> resources) {
        return new ClassLoader(GeneratedPiiModelTest.class.getClassLoader()) {
            @Override
            public Enumeration<URL> getResources(String name) throws java.io.IOException {
                List<URL> selected = resources.get(name);
                return selected == null
                        ? super.getResources(name)
                        : Collections.enumeration(selected);
            }
        };
    }
}
