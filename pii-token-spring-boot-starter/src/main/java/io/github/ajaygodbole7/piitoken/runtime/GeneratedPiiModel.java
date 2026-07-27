package io.github.ajaygodbole7.piitoken.runtime;

import io.github.ajaygodbole7.piitoken.descriptor.PiiDescriptorRegistry;
import io.github.ajaygodbole7.piitoken.descriptor.PiiFieldAccess;
import io.github.ajaygodbole7.piitoken.descriptor.PiiFieldDescriptor;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;

/**
 * Immutable aggregate of annotation-processor output visible to one
 * application class loader.
 */
public final class GeneratedPiiModel {

    private static final String MARKER_RESOURCE = "META-INF/pii/processor-marker.txt";
    private static final byte[] EXPECTED_MARKER =
            (PiiDescriptorRegistry.PROCESSOR_MARKER + "\n")
                    .getBytes(StandardCharsets.US_ASCII);

    private final List<PiiFieldAccess<?>> fields;
    private final List<PiiFieldDescriptor> descriptors;
    private final Map<Class<?>, List<PiiFieldAccess<?>>> fieldsByEntity;

    GeneratedPiiModel(List<PiiFieldAccess<?>> fields) {
        this.fields = fields.stream()
                .sorted(Comparator.comparing(field -> field.descriptor().id()))
                .toList();
        this.descriptors = this.fields.stream()
                .map(PiiFieldAccess::descriptor)
                .toList();
        Map<Class<?>, List<PiiFieldAccess<?>>> mutable = new LinkedHashMap<>();
        for (PiiFieldAccess<?> field : this.fields) {
            mutable.computeIfAbsent(field.entityType(), ignored -> new ArrayList<>())
                    .add(field);
        }
        Map<Class<?>, List<PiiFieldAccess<?>>> immutable = new LinkedHashMap<>();
        mutable.forEach((entity, entityFields) ->
                immutable.put(entity, List.copyOf(entityFields)));
        this.fieldsByEntity = Map.copyOf(immutable);
    }

    public static GeneratedPiiModel load(ClassLoader classLoader) {
        Objects.requireNonNull(classLoader, "classLoader");
        validateMarkers(classLoader);
        List<PiiFieldAccess<?>> fields = new ArrayList<>();
        Map<String, PiiFieldDescriptor> ids = new LinkedHashMap<>();
        Map<String, PiiFieldDescriptor> mappings = new LinkedHashMap<>();
        try {
            for (PiiDescriptorRegistry registry :
                    ServiceLoader.load(PiiDescriptorRegistry.class, classLoader)) {
                if (!PiiDescriptorRegistry.PROCESSOR_MARKER.equals(
                        registry.processorMarker())) {
                    throw invalidOutput();
                }
                List<PiiFieldAccess<?>> registryFields = registry.fields();
                if (registryFields == null) {
                    throw invalidOutput();
                }
                for (PiiFieldAccess<?> field : registryFields) {
                    validateField(field);
                    PiiFieldDescriptor descriptor = field.descriptor();
                    String mapping = descriptor.entityClassName() + "#" + descriptor.fieldName();
                    if (ids.putIfAbsent(descriptor.id(), descriptor) != null
                            || mappings.putIfAbsent(mapping, descriptor) != null) {
                        throw invalidOutput();
                    }
                    fields.add(field);
                }
            }
        }
        catch (ServiceConfigurationError | RuntimeException exception) {
            if (exception instanceof StartupValidationException validation) {
                throw validation;
            }
            throw invalidOutput();
        }
        fields.sort(Comparator.comparing(field -> field.descriptor().id()));
        return new GeneratedPiiModel(fields);
    }

    public List<PiiFieldAccess<?>> fields() {
        return fields;
    }

    public List<PiiFieldDescriptor> descriptors() {
        return descriptors;
    }

    public List<PiiFieldAccess<?>> fieldsFor(Object entity) {
        Objects.requireNonNull(entity, "entity");
        List<PiiFieldAccess<?>> matched = new ArrayList<>();
        fieldsByEntity.forEach((entityType, entityFields) -> {
            if (entityType.isInstance(entity)) {
                matched.addAll(entityFields);
            }
        });
        return List.copyOf(matched);
    }

    private static void validateMarkers(ClassLoader classLoader) {
        int markerCount = 0;
        try {
            Enumeration<URL> resources = classLoader.getResources(MARKER_RESOURCE);
            while (resources.hasMoreElements()) {
                markerCount++;
                try (InputStream input = resources.nextElement().openStream()) {
                    byte[] marker = input.readNBytes(EXPECTED_MARKER.length + 1);
                    if (!Arrays.equals(marker, EXPECTED_MARKER)
                            || input.read() != -1) {
                        throw invalidOutput();
                    }
                }
            }
        }
        catch (IOException exception) {
            throw invalidOutput();
        }
        if (markerCount == 0) {
            throw new StartupValidationException(StartupReason.GENERATED_OUTPUT_MISSING);
        }
    }

    private static void validateField(PiiFieldAccess<?> field) {
        if (field == null
                || field.entityType() == null
                || field.descriptor() == null
                || !field.entityType().getName().equals(
                        field.descriptor().entityClassName())) {
            throw invalidOutput();
        }
    }

    private static StartupValidationException invalidOutput() {
        return new StartupValidationException(StartupReason.GENERATED_OUTPUT_INVALID);
    }
}
