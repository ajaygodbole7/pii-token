package io.github.ajaygodbole7.piitoken.descriptor;

/**
 * Generated, non-reflective access to one protected entity property.
 *
 * @param <T> owning entity type
 */
public interface PiiFieldAccess<T> {

    Class<T> entityType();

    PiiFieldDescriptor descriptor();

    String readValue(T entity);

    void writeValue(T entity, String value);

    default String readLast4(T entity) {
        throw new UnsupportedOperationException("PII_FIELD_HAS_NO_LAST4");
    }

    default void writeLast4(T entity, String last4) {
        throw new UnsupportedOperationException("PII_FIELD_HAS_NO_LAST4");
    }
}
