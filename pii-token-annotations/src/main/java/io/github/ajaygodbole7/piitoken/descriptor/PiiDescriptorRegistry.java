package io.github.ajaygodbole7.piitoken.descriptor;

import java.util.List;

/**
 * Generated registry consumed by startup validation and runtime dispatch.
 */
public interface PiiDescriptorRegistry {

    String PROCESSOR_MARKER = "p1-jsr269-v1";

    /**
     * Marker proving that an annotation processor generated this registry.
     */
    String processorMarker();

    List<PiiFieldAccess<?>> fields();
}
