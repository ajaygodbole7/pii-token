package io.github.ajaygodbole7.piitoken.serialization;

import io.github.ajaygodbole7.piitoken.descriptor.PiiFieldAccess;
import io.github.ajaygodbole7.piitoken.runtime.GeneratedPiiModel;
import tools.jackson.databind.BeanDescription;
import tools.jackson.databind.SerializationConfig;
import tools.jackson.databind.module.SimpleModule;
import tools.jackson.databind.ser.BeanPropertyWriter;
import tools.jackson.databind.ser.ValueSerializerModifier;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Opt-in Jackson 3 module that removes protected token properties from
 * serialized entities. LAST4 companion properties are deliberately retained.
 */
public final class PiiProtectedFieldsJacksonModule extends SimpleModule {

    private static final long serialVersionUID = 1L;

    public PiiProtectedFieldsJacksonModule(GeneratedPiiModel generatedModel) {
        super("pii-protected-fields");
        Objects.requireNonNull(generatedModel, "generatedModel");
        setSerializerModifier(new ProtectedFieldModifier(
                protectedFields(generatedModel.fields())));
    }

    private static Map<Class<?>, Set<String>> protectedFields(
            List<PiiFieldAccess<?>> fields) {
        Map<Class<?>, Set<String>> mutable = new LinkedHashMap<>();
        for (PiiFieldAccess<?> field : fields) {
            mutable.computeIfAbsent(
                            field.entityType(),
                            ignored -> new LinkedHashSet<>())
                    .add(field.descriptor().fieldName());
        }
        Map<Class<?>, Set<String>> immutable = new LinkedHashMap<>();
        mutable.forEach((entityType, fieldNames) ->
                immutable.put(entityType, Set.copyOf(fieldNames)));
        return Map.copyOf(immutable);
    }

    private static final class ProtectedFieldModifier extends ValueSerializerModifier {

        private static final long serialVersionUID = 1L;

        private final Map<Class<?>, Set<String>> protectedFields;

        private ProtectedFieldModifier(Map<Class<?>, Set<String>> protectedFields) {
            this.protectedFields = protectedFields;
        }

        @Override
        public List<BeanPropertyWriter> changeProperties(
                SerializationConfig configuration,
                BeanDescription.Supplier beanDescription,
                List<BeanPropertyWriter> properties) {
            Set<String> denied = deniedFields(beanDescription.getBeanClass());
            if (denied.isEmpty()) {
                return properties;
            }
            return properties.stream()
                    .filter(property -> !denied.contains(property.getName()))
                    .toList();
        }

        private Set<String> deniedFields(Class<?> beanClass) {
            Set<String> denied = new LinkedHashSet<>();
            protectedFields.forEach((entityType, fields) -> {
                if (entityType.isAssignableFrom(beanClass)) {
                    denied.addAll(fields);
                }
            });
            return Set.copyOf(denied);
        }
    }
}
