package io.github.ajaygodbole7.piitoken.descriptor;

import io.github.ajaygodbole7.piitoken.annotation.Kind;
import io.github.ajaygodbole7.piitoken.annotation.Mask;

import java.util.Objects;

/**
 * Immutable logical identity emitted by the annotation processor.
 */
public record PiiFieldDescriptor(
        String id,
        Kind kind,
        boolean searchable,
        Mask mask,
        String entityClassName,
        String fieldName) {

    public PiiFieldDescriptor {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(mask, "mask");
        Objects.requireNonNull(entityClassName, "entityClassName");
        Objects.requireNonNull(fieldName, "fieldName");
    }
}
