package io.github.ajaygodbole7.piitoken.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Declares irreversible tokenization for one SSN or PAN field.
 *
 * <p>The original value cannot be recovered. Do not annotate a field if losing
 * the original value would create a business, legal, or operational incident.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface PII {

    String id();

    Kind kind();

    boolean searchable() default false;

    Mask mask() default Mask.NONE;
}
