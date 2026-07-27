package io.github.ajaygodbole7.piitoken.processor;

import io.github.ajaygodbole7.piitoken.annotation.Mask;
import io.github.ajaygodbole7.piitoken.annotation.PII;
import io.github.ajaygodbole7.piitoken.descriptor.DescriptorManifestCodec;
import io.github.ajaygodbole7.piitoken.descriptor.OwnerMigrationArtifacts;
import io.github.ajaygodbole7.piitoken.descriptor.PiiDescriptorRegistry;
import io.github.ajaygodbole7.piitoken.descriptor.PiiFieldDescriptor;

import javax.annotation.processing.AbstractProcessor;
import javax.annotation.processing.Filer;
import javax.annotation.processing.RoundEnvironment;
import javax.lang.model.SourceVersion;
import javax.lang.model.element.AnnotationMirror;
import javax.lang.model.element.Element;
import javax.lang.model.element.ElementKind;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.Modifier;
import javax.lang.model.element.NestingKind;
import javax.lang.model.element.PackageElement;
import javax.lang.model.element.TypeElement;
import javax.lang.model.element.VariableElement;
import javax.lang.model.type.TypeKind;
import javax.lang.model.type.TypeMirror;
import javax.tools.Diagnostic;
import javax.tools.JavaFileObject;
import javax.tools.StandardLocation;
import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Aggregating JSR-269 processor for the v1 @PII model.
 */
public final class PiiProcessor extends AbstractProcessor {

    static final String PROCESSOR_MARKER = PiiDescriptorRegistry.PROCESSOR_MARKER;

    private static final String ENTITY_ANNOTATION = "jakarta.persistence.Entity";
    private static final String ID_ANNOTATION = "jakarta.persistence.Id";
    private static final String ID_CLASS_ANNOTATION = "jakarta.persistence.IdClass";
    private static final String EMBEDDED_ID_ANNOTATION = "jakarta.persistence.EmbeddedId";
    private static final String ACCESS_ANNOTATION = "jakarta.persistence.Access";
    private static final String CONVERT_ANNOTATION = "jakarta.persistence.Convert";
    private static final String CONVERTS_ANNOTATION = "jakarta.persistence.Converts";
    private static final String CONVERTER_ANNOTATION = "jakarta.persistence.Converter";
    private static final String IMMUTABLE_ANNOTATION = "org.hibernate.annotations.Immutable";
    private static final String GENERATED_ANNOTATION = "org.hibernate.annotations.Generated";
    private static final String STRING = "java.lang.String";
    private static final String OBJECT = "java.lang.Object";
    private static final String VOID = "void";
    private static final Pattern ID = Pattern.compile("[a-z0-9.-]{3,64}");

    private final Map<String, String> ids = new HashMap<>();
    private final Set<String> processedFields = new HashSet<>();
    private final Set<String> generatedMetadata = new HashSet<>();
    private final List<PiiFieldDescriptor> descriptors = new ArrayList<>();
    private boolean invalid;
    private boolean resourcesWritten;

    @Override
    public Set<String> getSupportedAnnotationTypes() {
        // "*" makes a processor-present zero-PII build emit an empty marker
        // registry, which startup can distinguish from missing processor output.
        return Set.of("*");
    }

    @Override
    public SourceVersion getSupportedSourceVersion() {
        return SourceVersion.latestSupported();
    }

    @Override
    public boolean process(
            Set<? extends TypeElement> annotations,
            RoundEnvironment roundEnvironment) {
        if (resourcesWritten) {
            return false;
        }
        if (roundEnvironment.processingOver()) {
            resourcesWritten = true;
            if (!invalid) {
                try {
                    writeAggregateResources();
                }
                catch (IOException exception) {
                    processingEnv.getMessager().printMessage(
                            Diagnostic.Kind.ERROR,
                            "PII900 failed to generate @PII artifacts");
                }
            }
            return false;
        }

        List<EntityModel> entities = collectAndValidate(roundEnvironment);
        if (invalid) {
            return false;
        }
        try {
            for (EntityModel entity : entities) {
                String entityName = entity.type().getQualifiedName().toString();
                if (generatedMetadata.add(entityName)) {
                    writeEntityMetadata(entity.type(), entity.fields());
                    writeRepositoryFragment(entity);
                }
            }
        }
        catch (IOException exception) {
            invalid = true;
            processingEnv.getMessager().printMessage(
                    Diagnostic.Kind.ERROR,
                    "PII900 failed to generate @PII artifacts");
        }
        return false;
    }

    private List<EntityModel> collectAndValidate(
            RoundEnvironment roundEnvironment) {
        Map<TypeElement, List<FieldModel>> byEntity = new LinkedHashMap<>();
        Map<TypeElement, Set<String>> accessClassNames = new HashMap<>();
        boolean autoApplyConverter = hasAutoApplyConverter(roundEnvironment);

        for (Element element : roundEnvironment.getElementsAnnotatedWith(PII.class)) {
            if (element.getKind() != ElementKind.FIELD) {
                error(element, "PII003 @PII field must be java.lang.String");
                invalid = true;
                continue;
            }
            VariableElement field = (VariableElement) element;
            TypeElement owner = (TypeElement) field.getEnclosingElement();
            String fieldKey = owner.getQualifiedName() + "#" + field.getSimpleName();
            if (!processedFields.add(fieldKey)) {
                continue;
            }
            PII annotation = field.getAnnotation(PII.class);

            if (!ID.matcher(annotation.id()).matches()) {
                error(field, "PII001 invalid @PII id; expected [a-z0-9.-]{3,64}");
                invalid = true;
            }
            String prior = ids.putIfAbsent(annotation.id(), fieldKey);
            if (prior != null) {
                error(field, "PII002 duplicate @PII id: " + annotation.id());
                invalid = true;
            }
            if (!isString(field.asType())) {
                error(field, "PII003 @PII field must be java.lang.String");
                invalid = true;
            }
            if (owner.getNestingKind() != NestingKind.TOP_LEVEL
                    || !hasAnnotation(owner, ENTITY_ANNOTATION)) {
                error(field, "PII004 @PII owner must be a top-level jakarta.persistence.Entity");
                invalid = true;
            }
            if (hasNonObjectSuperclass(owner)) {
                error(field, "PII012 protected entity inheritance is not supported");
                invalid = true;
            }
            if (hasAnnotation(owner, ACCESS_ANNOTATION)
                    || hasAnnotation(field, ACCESS_ANNOTATION)
                    || hasAnnotatedMember(owner, ElementKind.METHOD, ACCESS_ANNOTATION)) {
                error(field, "PII013 protected entities require default field access; "
                        + "jakarta.persistence.Access overrides are not supported");
                invalid = true;
            }
            if (hasAnnotation(field, CONVERT_ANNOTATION)
                    || hasAnnotation(field, CONVERTS_ANNOTATION)
                    || autoApplyConverter) {
                error(field, "PII015 attribute converters on @PII fields are not supported");
                invalid = true;
            }
            if (owner.getKind() == ElementKind.RECORD
                    || hasAnnotation(owner, IMMUTABLE_ANNOTATION)
                    || hasAnnotation(field, IMMUTABLE_ANNOTATION)
                    || hasAnnotation(field, GENERATED_ANNOTATION)) {
                error(field, "PII016 generated or immutable @PII state is not supported");
                invalid = true;
            }
            if (field.getModifiers().contains(Modifier.STATIC)
                    || field.getModifiers().contains(Modifier.FINAL)) {
                error(field, "PII007 @PII field must be mutable and non-static");
                invalid = true;
            }

            String property = field.getSimpleName().toString();
            String accessorSuffix = beanSuffix(property);
            if (!hasAccessors(owner, accessorSuffix)) {
                error(field, "PII006 @PII field requires accessible get"
                        + accessorSuffix + "() and set" + accessorSuffix + "(String)");
                invalid = true;
            }

            if (annotation.mask() == Mask.LAST4) {
                String companionName = property + "Last4";
                VariableElement companion = findDeclaredField(owner, companionName);
                if (companion == null || !isString(companion.asType())) {
                    error(field, "PII005 LAST4 requires String companion field '"
                            + companionName + "'");
                    invalid = true;
                }
                else {
                    if (companion.getModifiers().contains(Modifier.STATIC)
                            || companion.getModifiers().contains(Modifier.FINAL)) {
                        error(companion, "PII007 LAST4 companion must be mutable and non-static");
                        invalid = true;
                    }
                    String companionSuffix = beanSuffix(companionName);
                    if (!hasAccessors(owner, companionSuffix)) {
                        error(companion, "PII006 LAST4 companion requires accessible get"
                                + companionSuffix + "() and set" + companionSuffix + "(String)");
                        invalid = true;
                    }
                }
            }

            String accessClassName = accessorSuffix + "Access";
            if (!accessClassNames.computeIfAbsent(owner, ignored -> new HashSet<>())
                    .add(accessClassName)) {
                error(field, "PII008 generated accessor name collision");
                invalid = true;
            }
            FieldModel model = new FieldModel(
                    owner,
                    field,
                    annotation,
                    accessClassName);
            byEntity.computeIfAbsent(owner, ignored -> new ArrayList<>()).add(model);
            descriptors.add(model.descriptor());
        }

        List<EntityModel> entities = new ArrayList<>();
        for (Map.Entry<TypeElement, List<FieldModel>> entry : byEntity.entrySet()) {
            TypeElement owner = entry.getKey();
            List<FieldModel> models = entry.getValue();
            models.sort(Comparator.comparing(model -> model.annotation().id()));
            List<VariableElement> idFields = processingEnv.getElementUtils()
                    .getAllMembers(owner)
                    .stream()
                    .filter(element -> element.getKind() == ElementKind.FIELD)
                    .map(VariableElement.class::cast)
                    .filter(field -> hasAnnotation(field, ID_ANNOTATION))
                    .toList();
            boolean propertyId = processingEnv.getElementUtils()
                    .getAllMembers(owner)
                    .stream()
                    .filter(element -> element.getKind() == ElementKind.METHOD)
                    .anyMatch(method -> hasAnnotation(method, ID_ANNOTATION));
            boolean embeddedOrIdClass = hasAnnotation(owner, ID_CLASS_ANNOTATION)
                    || hasAnnotatedMember(
                            owner,
                            ElementKind.FIELD,
                            EMBEDDED_ID_ANNOTATION)
                    || hasAnnotatedMember(
                            owner,
                            ElementKind.METHOD,
                            EMBEDDED_ID_ANNOTATION);
            if (propertyId) {
                error(models.getFirst().field(),
                        "PII013 protected entities require field access; "
                                + "property-access @Id is not supported");
                invalid = true;
                continue;
            }
            if (embeddedOrIdClass || idFields.size() > 1) {
                error(models.getFirst().field(),
                        "PII014 embedded or composite entity ids are not supported");
                invalid = true;
                continue;
            }
            if (idFields.isEmpty()) {
                error(models.getFirst().field(),
                        "PII009 protected entity requires exactly one field-level "
                                + "jakarta.persistence.Id");
                invalid = true;
                continue;
            }
            if (!owner.getTypeParameters().isEmpty()) {
                error(models.getFirst().field(),
                        "PII010 generic protected entities are not supported");
                invalid = true;
                continue;
            }
            if (generatedTypeExists(owner, owner.getSimpleName() + "PiiMetadata")
                    || generatedTypeExists(
                            owner,
                            owner.getSimpleName() + "PiiRepositoryFragment")
                    || generatedTypeExists(
                            owner,
                            owner.getSimpleName() + "PiiRepositoryFragmentImpl")) {
                error(models.getFirst().field(),
                        "PII011 generated @PII type name collides with an existing type");
                invalid = true;
                continue;
            }
            entities.add(new EntityModel(owner, idFields.getFirst().asType(), models));
        }
        entities.sort(Comparator.comparing(
                entity -> entity.type().getQualifiedName().toString()));
        return entities;
    }

    private void writeEntityMetadata(TypeElement entity, List<FieldModel> fields)
            throws IOException {
        PackageElement packageElement = processingEnv.getElementUtils().getPackageOf(entity);
        String packageName = packageElement.getQualifiedName().toString();
        String entityName = entity.getSimpleName().toString();
        String metadataName = entityName + "PiiMetadata";
        JavaFileObject file = processingEnv.getFiler().createSourceFile(
                packageName + "." + metadataName,
                entity);
        try (Writer writer = file.openWriter()) {
            writer.write("package " + packageName + ";\n\n");
            writer.write("import io.github.ajaygodbole7.piitoken.annotation.Kind;\n");
            writer.write("import io.github.ajaygodbole7.piitoken.annotation.Mask;\n");
            writer.write("import io.github.ajaygodbole7.piitoken.descriptor.PiiDescriptorRegistry;\n");
            writer.write("import io.github.ajaygodbole7.piitoken.descriptor.PiiFieldAccess;\n");
            writer.write("import io.github.ajaygodbole7.piitoken.descriptor.PiiFieldDescriptor;\n\n");
            writer.write("public final class " + metadataName
                    + " implements PiiDescriptorRegistry {\n\n");
            writer.write("    public " + metadataName + "() {\n    }\n\n");
            writer.write("    @Override\n");
            writer.write("    public String processorMarker() {\n");
            writer.write("        return \"" + PROCESSOR_MARKER + "\";\n");
            writer.write("    }\n\n");
            writer.write("    @Override\n");
            writer.write("    public java.util.List<PiiFieldAccess<?>> fields() {\n");
            if (fields.isEmpty()) {
                writer.write("        return java.util.List.of();\n");
            }
            else {
                writer.write("        return java.util.List.of(");
                for (int index = 0; index < fields.size(); index++) {
                    if (index > 0) {
                        writer.write(", ");
                    }
                    writer.write("new " + fields.get(index).accessClassName() + "()");
                }
                writer.write(");\n");
            }
            writer.write("    }\n\n");

            for (FieldModel model : fields) {
                writeAccessClass(writer, entityName, model);
            }
            writer.write("}\n");
        }
    }

    private static void writeAccessClass(
            Writer writer,
            String entityName,
            FieldModel model) throws IOException {
        String property = model.field().getSimpleName().toString();
        String suffix = beanSuffix(property);
        PII annotation = model.annotation();
        writer.write("    private static final class " + model.accessClassName()
                + " implements PiiFieldAccess<" + entityName + "> {\n\n");
        writer.write("        private static final PiiFieldDescriptor DESCRIPTOR =\n");
        writer.write("                new PiiFieldDescriptor(\"" + annotation.id() + "\", Kind."
                + annotation.kind().name() + ", " + annotation.searchable() + ", Mask."
                + annotation.mask().name() + ", \"" + model.owner().getQualifiedName()
                + "\", \"" + property + "\");\n\n");
        writer.write("        @Override\n");
        writer.write("        public Class<" + entityName + "> entityType() {\n");
        writer.write("            return " + entityName + ".class;\n");
        writer.write("        }\n\n");
        writer.write("        @Override\n");
        writer.write("        public PiiFieldDescriptor descriptor() {\n");
        writer.write("            return DESCRIPTOR;\n");
        writer.write("        }\n\n");
        writer.write("        @Override\n");
        writer.write("        public String readValue(" + entityName + " entity) {\n");
        writer.write("            return entity.get" + suffix + "();\n");
        writer.write("        }\n\n");
        writer.write("        @Override\n");
        writer.write("        public void writeValue(" + entityName + " entity, String value) {\n");
        writer.write("            entity.set" + suffix + "(value);\n");
        writer.write("        }\n");
        if (annotation.mask() == Mask.LAST4) {
            String companionSuffix = beanSuffix(property + "Last4");
            writer.write("\n        @Override\n");
            writer.write("        public String readLast4(" + entityName + " entity) {\n");
            writer.write("            return entity.get" + companionSuffix + "();\n");
            writer.write("        }\n\n");
            writer.write("        @Override\n");
            writer.write("        public void writeLast4(" + entityName + " entity, String last4) {\n");
            writer.write("            entity.set" + companionSuffix + "(last4);\n");
            writer.write("        }\n");
        }
        writer.write("    }\n\n");
    }

    private void writeRepositoryFragment(EntityModel entity) throws IOException {
        PackageElement packageElement =
                processingEnv.getElementUtils().getPackageOf(entity.type());
        String packageName = packageElement.getQualifiedName().toString();
        String entityName = entity.type().getSimpleName().toString();
        String fragmentName = entityName + "PiiRepositoryFragment";
        String implementationName = fragmentName + "Impl";
        String idType = entity.idType().toString();

        JavaFileObject interfaceFile = processingEnv.getFiler().createSourceFile(
                packageName + "." + fragmentName,
                entity.type());
        try (Writer writer = interfaceFile.openWriter()) {
            writer.write("package " + packageName + ";\n\n");
            writer.write("public interface " + fragmentName + " {\n\n");
            for (FieldModel field : entity.fields()) {
                writeFragmentInterfaceMethods(writer, entityName, idType, field);
            }
            writer.write("}\n");
        }

        JavaFileObject implementationFile = processingEnv.getFiler().createSourceFile(
                packageName + "." + implementationName,
                entity.type());
        try (Writer writer = implementationFile.openWriter()) {
            writer.write("package " + packageName + ";\n\n");
            writer.write("import io.github.ajaygodbole7.piitoken.protocol."
                    + "GeneratedPiiJpaOperations;\n");
            writer.write("import jakarta.persistence.EntityManager;\n");
            writer.write("import jakarta.persistence.PersistenceContext;\n");
            writer.write("import org.springframework.transaction.annotation.Transactional;\n\n");
            writer.write("public class " + implementationName
                    + " implements " + fragmentName + " {\n\n");
            writer.write("    @PersistenceContext\n");
            writer.write("    private EntityManager entityManager;\n\n");
            writer.write("    private final GeneratedPiiJpaOperations piiOperations;\n\n");
            writer.write("    public " + implementationName
                    + "(GeneratedPiiJpaOperations piiOperations) {\n");
            writer.write("        this.piiOperations = piiOperations;\n");
            writer.write("    }\n\n");
            for (FieldModel field : entity.fields()) {
                writeFragmentImplementationMethods(writer, entityName, idType, field);
            }
            writer.write("}\n");
        }
    }

    private static void writeFragmentInterfaceMethods(
            Writer writer,
            String entityName,
            String idType,
            FieldModel field) throws IOException {
        String suffix = beanSuffix(field.field().getSimpleName().toString());
        if (field.annotation().searchable()) {
            writer.write("    boolean existsBy" + suffix + "(String candidate);\n\n");
            writer.write("    java.util.List<" + entityName + "> findAllBy"
                    + suffix + "(String candidate);\n\n");
        }
        writer.write("    boolean " + field.field().getSimpleName() + "Matches("
                + idType + " id, String candidate);\n\n");
        writer.write("    boolean replace" + suffix + "("
                + idType + " id, String value);\n\n");
    }

    private static void writeFragmentImplementationMethods(
            Writer writer,
            String entityName,
            String idType,
            FieldModel field) throws IOException {
        String property = field.field().getSimpleName().toString();
        String suffix = beanSuffix(property);
        String id = field.annotation().id();
        if (field.annotation().searchable()) {
            writer.write("    @Override\n");
            writer.write("    public boolean existsBy" + suffix + "(String candidate) {\n");
            writer.write("        return piiOperations.existsBy(\n");
            writer.write("                entityManager, " + entityName + ".class, \""
                    + id + "\", \"" + property + "\", candidate);\n");
            writer.write("    }\n\n");
            writer.write("    @Override\n");
            writer.write("    public java.util.List<" + entityName + "> findAllBy"
                    + suffix + "(String candidate) {\n");
            writer.write("        return piiOperations.findAllBy(\n");
            writer.write("                entityManager, " + entityName + ".class, \""
                    + id + "\", \"" + property + "\", candidate);\n");
            writer.write("    }\n\n");
        }
        writer.write("    @Override\n");
        writer.write("    public boolean " + property + "Matches("
                + idType + " id, String candidate) {\n");
        writer.write("        return piiOperations.matches(\n");
        writer.write("                entityManager, " + entityName + ".class, id, \""
                + id + "\", \"" + property + "\", candidate, "
                + entityName + "::get" + suffix + ");\n");
        writer.write("    }\n\n");
        writer.write("    @Override\n");
        writer.write("    @Transactional\n");
        writer.write("    public boolean replace" + suffix + "("
                + idType + " id, String value) {\n");
        writer.write("        boolean replaced = piiOperations.replace(\n");
        writer.write("                entityManager, " + entityName + ".class, id, \""
                + id + "\", \"" + property + "\", value, "
                + entityName + "::set" + suffix + ");\n");
        writer.write("        if (replaced) {\n");
        writer.write("            entityManager.flush();\n");
        writer.write("        }\n");
        writer.write("        return replaced;\n");
        writer.write("    }\n\n");
    }

    private void writeAggregateResources() throws IOException {
        if (!generatedMetadata.isEmpty()) {
            StringBuilder services = new StringBuilder();
            for (String entityName : generatedMetadata.stream().sorted().toList()) {
                int separator = entityName.lastIndexOf('.');
                String packageName = entityName.substring(0, separator);
                String simpleName = entityName.substring(separator + 1);
                services.append(packageName)
                        .append('.')
                        .append(simpleName)
                        .append("PiiMetadata\n");
            }
            writeResource(
                    "META-INF/services/io.github.ajaygodbole7.piitoken.descriptor.PiiDescriptorRegistry",
                    services.toString());
        }
        writeResource("META-INF/pii/processor-marker.txt", PROCESSOR_MARKER + "\n");
        List<PiiFieldDescriptor> canonical = descriptors.stream()
                .sorted(Comparator.comparing(PiiFieldDescriptor::id))
                .toList();
        String manifest = DescriptorManifestCodec.encode(canonical);
        writeResource("META-INF/pii/descriptor-manifest.txt", manifest);
        writeResource(
                "META-INF/pii/descriptor-fingerprint.txt",
                DescriptorManifestCodec.fingerprint(manifest));
        writeResource(
                "META-INF/pii/owner-migration-template.sql",
                OwnerMigrationArtifacts.migrationPlan(canonical));
        for (PiiFieldDescriptor field : canonical) {
            writeResource(
                    OwnerMigrationArtifacts.fieldBlockResource(field.id()),
                    OwnerMigrationArtifacts.fieldDdl(field));
        }
    }

    private void writeResource(String name, String value) throws IOException {
        Filer filer = processingEnv.getFiler();
        try (Writer writer = filer.createResource(StandardLocation.CLASS_OUTPUT, "", name)
                .openWriter()) {
            writer.write(value);
        }
    }

    private boolean hasAccessors(TypeElement owner, String suffix) {
        boolean getter = false;
        boolean setter = false;
        String getterName = "get" + suffix;
        String setterName = "set" + suffix;
        for (Element member : processingEnv.getElementUtils().getAllMembers(owner)) {
            if (member.getKind() != ElementKind.METHOD) {
                continue;
            }
            ExecutableElement method = (ExecutableElement) member;
            if (!isAccessibleFromEntityPackage(owner, method)) {
                continue;
            }
            if (method.getSimpleName().contentEquals(getterName)
                    && method.getParameters().isEmpty()
                    && isString(method.getReturnType())) {
                getter = true;
            }
            if (method.getSimpleName().contentEquals(setterName)
                    && method.getParameters().size() == 1
                    && isString(method.getParameters().getFirst().asType())
                    && method.getReturnType().toString().equals(VOID)) {
                setter = true;
            }
        }
        return getter && setter;
    }

    private boolean isAccessibleFromEntityPackage(
            TypeElement owner,
            ExecutableElement method) {
        Set<Modifier> modifiers = method.getModifiers();
        if (modifiers.contains(Modifier.PRIVATE) || modifiers.contains(Modifier.STATIC)) {
            return false;
        }
        if (modifiers.contains(Modifier.PUBLIC)) {
            return true;
        }
        PackageElement ownerPackage = processingEnv.getElementUtils().getPackageOf(owner);
        PackageElement methodPackage = processingEnv.getElementUtils()
                .getPackageOf(method.getEnclosingElement());
        return ownerPackage.getQualifiedName().contentEquals(methodPackage.getQualifiedName());
    }

    private boolean isString(TypeMirror type) {
        TypeElement string = processingEnv.getElementUtils().getTypeElement(STRING);
        return string != null && processingEnv.getTypeUtils().isSameType(type, string.asType());
    }

    private boolean hasNonObjectSuperclass(TypeElement owner) {
        TypeMirror superclass = owner.getSuperclass();
        if (superclass.getKind() == TypeKind.NONE) {
            return false;
        }
        TypeElement object = processingEnv.getElementUtils().getTypeElement(OBJECT);
        return object == null
                || !processingEnv.getTypeUtils().isSameType(superclass, object.asType());
    }

    private boolean hasAutoApplyConverter(RoundEnvironment roundEnvironment) {
        TypeElement converter = processingEnv.getElementUtils()
                .getTypeElement(CONVERTER_ANNOTATION);
        if (converter == null) {
            return false;
        }
        for (Element element : roundEnvironment.getElementsAnnotatedWith(converter)) {
            for (AnnotationMirror annotation : element.getAnnotationMirrors()) {
                if (!(annotation.getAnnotationType().asElement() instanceof TypeElement type)
                        || !type.getQualifiedName().contentEquals(CONVERTER_ANNOTATION)) {
                    continue;
                }
                for (Map.Entry<? extends ExecutableElement, ? extends
                        javax.lang.model.element.AnnotationValue> value
                        : processingEnv.getElementUtils()
                        .getElementValuesWithDefaults(annotation)
                        .entrySet()) {
                    if (value.getKey().getSimpleName().contentEquals("autoApply")
                            && Boolean.TRUE.equals(value.getValue().getValue())) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private static VariableElement findDeclaredField(TypeElement owner, String name) {
        return owner.getEnclosedElements().stream()
                .filter(element -> element.getKind() == ElementKind.FIELD)
                .map(VariableElement.class::cast)
                .filter(field -> field.getSimpleName().contentEquals(name))
                .findFirst()
                .orElse(null);
    }

    private static boolean hasAnnotation(Element element, String qualifiedName) {
        for (AnnotationMirror annotation : element.getAnnotationMirrors()) {
            if (annotation.getAnnotationType().asElement() instanceof TypeElement type
                    && type.getQualifiedName().contentEquals(qualifiedName)) {
                return true;
            }
        }
        return false;
    }

    private boolean hasAnnotatedMember(
            TypeElement owner,
            ElementKind kind,
            String annotationName) {
        return processingEnv.getElementUtils()
                .getAllMembers(owner)
                .stream()
                .filter(element -> element.getKind() == kind)
                .anyMatch(element -> hasAnnotation(element, annotationName));
    }

    private static String beanSuffix(String fieldName) {
        return fieldName.substring(0, 1).toUpperCase(Locale.ROOT) + fieldName.substring(1);
    }

    private boolean generatedTypeExists(TypeElement owner, String simpleName) {
        PackageElement packageElement = processingEnv.getElementUtils().getPackageOf(owner);
        return processingEnv.getElementUtils().getTypeElement(
                packageElement.getQualifiedName() + "." + simpleName) != null;
    }

    private void error(Element element, String message) {
        processingEnv.getMessager().printMessage(Diagnostic.Kind.ERROR, message, element);
    }

    private record FieldModel(
            TypeElement owner,
            VariableElement field,
            PII annotation,
            String accessClassName) {

        PiiFieldDescriptor descriptor() {
            return new PiiFieldDescriptor(
                    annotation.id(),
                    annotation.kind(),
                    annotation.searchable(),
                    annotation.mask(),
                    owner.getQualifiedName().toString(),
                    field.getSimpleName().toString());
        }
    }

    private record EntityModel(
            TypeElement type,
            TypeMirror idType,
            List<FieldModel> fields) {
    }

}
