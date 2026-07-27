package io.github.ajaygodbole7.piitoken.processor;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.annotation.processing.AbstractProcessor;
import javax.annotation.processing.Processor;
import javax.annotation.processing.RoundEnvironment;
import javax.lang.model.SourceVersion;
import javax.lang.model.element.TypeElement;
import javax.tools.Diagnostic;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.StandardLocation;
import javax.tools.ToolProvider;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class PiiProcessorTest {

    @TempDir
    Path temporary;

    @Test
    void generatesReadableAccessRegistryAndCanonicalManifest() throws Exception {
        Compilation result = compile(
                source("demo.Customer", """
                        package demo;
                        import io.github.ajaygodbole7.piitoken.annotation.*;
                        @jakarta.persistence.Entity
                        class Customer {
                            @jakarta.persistence.Id
                            private java.util.UUID id;
                            @PII(id = "customer.ssn", kind = Kind.SSN,
                                 searchable = true, mask = Mask.LAST4)
                            private String ssn;
                            private String ssnLast4;
                            @PII(id = "customer.pan", kind = Kind.PAN)
                            private String pan;

                            String getSsn() { return ssn; }
                            void setSsn(String value) { ssn = value; }
                            String getSsnLast4() { return ssnLast4; }
                            void setSsnLast4(String value) { ssnLast4 = value; }
                            String getPan() { return pan; }
                            void setPan(String value) { pan = value; }
                        }
                        """));

        assertThat(result.success())
                .withFailMessage(result.errorMessages().toString())
                .isTrue();
        String metadata = Files.readString(result.generatedSources()
                .resolve("demo/CustomerPiiMetadata.java"));
        String fragment = Files.readString(result.generatedSources()
                .resolve("demo/CustomerPiiRepositoryFragment.java"));
        String implementation = Files.readString(result.generatedSources()
                .resolve("demo/CustomerPiiRepositoryFragmentImpl.java"));

        assertThat(metadata)
                .contains("implements PiiDescriptorRegistry")
                .contains("final class SsnAccess implements PiiFieldAccess<Customer>")
                .contains("return entity.getSsn();")
                .contains("entity.setSsn(value);")
                .contains("entity.setSsnLast4(last4);")
                .doesNotContain("java.lang.reflect");
        assertThat(fragment)
                .contains("boolean existsBySsn(String candidate);")
                .contains("java.util.List<Customer> findAllBySsn(String candidate);")
                .contains("boolean ssnMatches(java.util.UUID id, String candidate);")
                .contains("boolean replaceSsn(java.util.UUID id, String value);")
                .contains("boolean panMatches(java.util.UUID id, String candidate);")
                .contains("boolean replacePan(java.util.UUID id, String value);")
                .doesNotContain(
                        "Optional",
                        "findBySsn",
                        "existsByPan",
                        "findAllByPan",
                        "decrypt",
                        "recover",
                        "token(");
        assertThat(implementation)
                .contains("public class CustomerPiiRepositoryFragmentImpl")
                .contains("GeneratedPiiJpaOperations", "piiOperations.existsBy(")
                .contains("Customer::getSsn", "Customer::setSsn")
                .contains("entityManager.flush();")
                .doesNotContain("public final class CustomerPiiRepositoryFragmentImpl")
                .doesNotContain("java.lang.reflect");
        assertThat(Files.readString(result.classes().resolve("META-INF/pii/descriptor-manifest.txt")))
                .isEqualTo("""
                        customer.pan|PAN|false|NONE|demo.Customer|pan
                        customer.ssn|SSN|true|LAST4|demo.Customer|ssn""");
        assertThat(Files.readString(result.classes().resolve("META-INF/pii/descriptor-fingerprint.txt")))
                .matches("[0-9a-f]{64}");
        assertThat(Files.readString(result.classes().resolve(
                "META-INF/services/io.github.ajaygodbole7.piitoken.descriptor.PiiDescriptorRegistry")))
                .isEqualTo("demo.CustomerPiiMetadata\n");
        assertThat(Files.readString(result.classes().resolve("META-INF/pii/processor-marker.txt")))
                .isEqualTo("p1-jsr269-v1\n");
        String migrationPlan = Files.readString(result.classes().resolve(
                "META-INF/pii/owner-migration-template.sql"));
        String ssnMigration = Files.readString(result.classes().resolve(
                "META-INF/pii/migrations/fields/customer.ssn.sql"));
        String panMigration = Files.readString(result.classes().resolve(
                "META-INF/pii/migrations/fields/customer.pan.sql"));
        assertThat(migrationPlan)
                .contains(
                        "customer.ssn -> META-INF/pii/migrations/fields/customer.ssn.sql",
                        "customer.pan -> META-INF/pii/migrations/fields/customer.pan.sql",
                        "UPDATE pii_security.pii_policy_registry",
                        "descriptor_manifest = 'customer.pan|PAN|false|NONE|demo.Customer|pan",
                        "AND descriptor_fingerprint = "
                                + "'<currently-approved-descriptor-fingerprint>'")
                .doesNotContain("ALTER TABLE", "CREATE INDEX");
        assertThat(ssnMigration)
                .contains(
                        "-- BEGIN PII FIELD BLOCK: customer.ssn",
                        "<column_customer_ssn> ~ '^b2\\.",
                        "<suffix_column_customer_ssn> ~ '^[0-9]{4}$'",
                        "CREATE INDEX <index_customer_ssn_token>")
                .doesNotContain("customer.pan");
        assertThat(panMigration)
                .contains(
                        "-- BEGIN PII FIELD BLOCK: customer.pan",
                        "<column_customer_pan> ~ '^v2\\.")
                .doesNotContain(
                        "customer.ssn",
                        "CREATE INDEX <index_customer_pan_token>");
    }

    @Test
    void emitsResourceMarkerWhenNoPiiFieldsExist() throws Exception {
        Compilation result = compile(source("demo.Plain", """
                package demo;
                final class Plain {}
                """));

        assertThat(result.success()).isTrue();
        assertThat(Files.readString(result.classes().resolve("META-INF/pii/descriptor-manifest.txt")))
                .isEmpty();
        assertThat(Files.readString(result.classes().resolve("META-INF/pii/processor-marker.txt")))
                .isEqualTo("p1-jsr269-v1\n");
        assertThat(Files.readString(result.classes().resolve(
                "META-INF/pii/owner-migration-template.sql")))
                .contains("The library never executes this SQL.")
                .contains("UPDATE pii_security.pii_policy_registry")
                .doesNotContain("ALTER TABLE");
        assertThat(result.classes().resolve(
                "META-INF/services/io.github.ajaygodbole7.piitoken.descriptor.PiiDescriptorRegistry"))
                .doesNotExist();
    }

    @Test
    void rejectsDuplicateIdsAcrossEntities() throws Exception {
        Compilation result = compile(
                validEntity("demo.Customer", "customer.ssn"),
                validEntity("demo.OtherCustomer", "customer.ssn"));

        assertThat(result.success()).isFalse();
        assertThat(result.errorMessages())
                .anyMatch(message -> message.equals("PII002 duplicate @PII id: customer.ssn"));
    }

    @Test
    void rejectsInvalidIdAndNonStringField() throws Exception {
        Compilation result = compile(
                source("demo.Customer", """
                        package demo;
                        import io.github.ajaygodbole7.piitoken.annotation.*;
                        @jakarta.persistence.Entity
                        class Customer {
                            @jakarta.persistence.Id
                            private long id;
                            @PII(id = "Customer|SSN", kind = Kind.SSN)
                            private long ssn;
                            long getSsn() { return ssn; }
                            void setSsn(long value) { ssn = value; }
                        }
                        """));

        assertThat(result.success()).isFalse();
        assertThat(result.errorMessages())
                .contains("PII001 invalid @PII id; expected [a-z0-9.-]{3,64}")
                .contains("PII003 @PII field must be java.lang.String");
    }

    @Test
    void rejectsMissingLast4CompanionAndMissingAccessors() throws Exception {
        Compilation result = compile(
                source("demo.Customer", """
                        package demo;
                        import io.github.ajaygodbole7.piitoken.annotation.*;
                        @jakarta.persistence.Entity
                        class Customer {
                            @jakarta.persistence.Id
                            private long id;
                            @PII(id = "customer.ssn", kind = Kind.SSN, mask = Mask.LAST4)
                            private String ssn;
                        }
                        """));

        assertThat(result.success()).isFalse();
        assertThat(result.errorMessages())
                .contains("PII005 LAST4 requires String companion field 'ssnLast4'")
                .contains("PII006 @PII field requires accessible getSsn() and setSsn(String)");
    }

    @Test
    void rejectsFieldOutsideJpaEntity() throws Exception {
        Compilation result = compile(source("demo.Customer", """
                package demo;
                import io.github.ajaygodbole7.piitoken.annotation.*;
                class Customer {
                    @jakarta.persistence.Id
                    private long id;
                    @PII(id = "customer.ssn", kind = Kind.SSN)
                    private String ssn;
                    String getSsn() { return ssn; }
                    void setSsn(String value) { ssn = value; }
                }
                """));

        assertThat(result.success()).isFalse();
        assertThat(result.errorMessages()).contains(
                "PII004 @PII owner must be a top-level jakarta.persistence.Entity");
    }

    @Test
    void aggregatesPiiEntitiesIntroducedInLaterProcessingRounds() throws Exception {
        Compilation result = compile(
                List.of(new PiiProcessor(), new LateEntityProcessor()),
                source("demo.Seed", """
                        package demo;
                        final class Seed {}
                        """));

        assertThat(result.success())
                .withFailMessage(result.errorMessages().toString())
                .isTrue();
        assertThat(result.generatedSources().resolve("demo/GeneratedCustomerPiiMetadata.java"))
                .exists();
        assertThat(Files.readString(result.classes().resolve("META-INF/pii/descriptor-manifest.txt")))
                .isEqualTo("generated.ssn|SSN|false|NONE|demo.GeneratedCustomer|ssn");
        assertThat(Files.readString(result.classes().resolve(
                "META-INF/services/io.github.ajaygodbole7.piitoken.descriptor.PiiDescriptorRegistry")))
                .isEqualTo("demo.GeneratedCustomerPiiMetadata\n");
    }

    @Test
    void rejectsMissingOrCompositeFieldLevelJpaId() throws Exception {
        Compilation missing = compile(source("demo.MissingId", """
                package demo;
                import io.github.ajaygodbole7.piitoken.annotation.*;
                @jakarta.persistence.Entity
                class MissingId {
                    @PII(id = "missing.ssn", kind = Kind.SSN)
                    private String ssn;
                    String getSsn() { return ssn; }
                    void setSsn(String value) { ssn = value; }
                }
                """));
        Compilation composite = compile(source("demo.CompositeId", """
                package demo;
                import io.github.ajaygodbole7.piitoken.annotation.*;
                @jakarta.persistence.Entity
                class CompositeId {
                    @jakarta.persistence.Id private long tenantId;
                    @jakarta.persistence.Id private long customerId;
                    @PII(id = "composite.ssn", kind = Kind.SSN)
                    private String ssn;
                    String getSsn() { return ssn; }
                    void setSsn(String value) { ssn = value; }
                }
                """));

        assertThat(missing.errorMessages()).contains(
                "PII009 protected entity requires exactly one field-level jakarta.persistence.Id");
        assertThat(composite.errorMessages()).contains(
                "PII014 embedded or composite entity ids are not supported");
    }

    @Test
    void rejectsUnprovenJpaEntityShapesWithSpecificDiagnostics() throws Exception {
        Compilation inheritance = compile(
                source("demo.Base", """
                        package demo;
                        class Base {}
                        """),
                source("demo.InheritedCustomer", """
                        package demo;
                        import io.github.ajaygodbole7.piitoken.annotation.*;
                        @jakarta.persistence.Entity
                        class InheritedCustomer extends Base {
                            @jakarta.persistence.Id private long id;
                            @PII(id = "inherited.ssn", kind = Kind.SSN)
                            private String ssn;
                            String getSsn() { return ssn; }
                            void setSsn(String value) { ssn = value; }
                        }
                        """));
        Compilation propertyAccess = compile(source("demo.PropertyCustomer", """
                package demo;
                import io.github.ajaygodbole7.piitoken.annotation.*;
                @jakarta.persistence.Entity
                class PropertyCustomer {
                    private long id;
                    @PII(id = "property.ssn", kind = Kind.SSN)
                    private String ssn;
                    @jakarta.persistence.Id long getId() { return id; }
                    String getSsn() { return ssn; }
                    void setSsn(String value) { ssn = value; }
                }
                """));
        Compilation embeddedId = compile(source("demo.EmbeddedCustomer", """
                package demo;
                import io.github.ajaygodbole7.piitoken.annotation.*;
                @jakarta.persistence.Entity
                class EmbeddedCustomer {
                    @jakarta.persistence.EmbeddedId private Object id;
                    @PII(id = "embedded.ssn", kind = Kind.SSN)
                    private String ssn;
                    String getSsn() { return ssn; }
                    void setSsn(String value) { ssn = value; }
                }
                """));
        Compilation propertyEmbeddedId = compile(source("demo.PropertyEmbeddedCustomer", """
                package demo;
                import io.github.ajaygodbole7.piitoken.annotation.*;
                @jakarta.persistence.Entity
                class PropertyEmbeddedCustomer {
                    private Object id;
                    @PII(id = "property-embedded.ssn", kind = Kind.SSN)
                    private String ssn;
                    @jakarta.persistence.EmbeddedId Object getId() { return id; }
                    String getSsn() { return ssn; }
                    void setSsn(String value) { ssn = value; }
                }
                """));
        Compilation converted = compile(source("demo.ConvertedCustomer", """
                package demo;
                import io.github.ajaygodbole7.piitoken.annotation.*;
                @jakarta.persistence.Entity
                class ConvertedCustomer {
                    @jakarta.persistence.Id private long id;
                    @jakarta.persistence.Convert
                    @PII(id = "converted.ssn", kind = Kind.SSN)
                    private String ssn;
                    String getSsn() { return ssn; }
                    void setSsn(String value) { ssn = value; }
                }
                """));
        Compilation groupedConverters = compile(source("demo.GroupConvertedCustomer", """
                package demo;
                import io.github.ajaygodbole7.piitoken.annotation.*;
                @jakarta.persistence.Entity
                class GroupConvertedCustomer {
                    @jakarta.persistence.Id private long id;
                    @jakarta.persistence.Converts({@jakarta.persistence.Convert})
                    @PII(id = "group-converted.ssn", kind = Kind.SSN)
                    private String ssn;
                    String getSsn() { return ssn; }
                    void setSsn(String value) { ssn = value; }
                }
                """));
        Compilation immutable = compile(source("demo.ImmutableCustomer", """
                package demo;
                import io.github.ajaygodbole7.piitoken.annotation.*;
                @jakarta.persistence.Entity
                @org.hibernate.annotations.Immutable
                class ImmutableCustomer {
                    @jakarta.persistence.Id private long id;
                    @PII(id = "immutable.ssn", kind = Kind.SSN)
                    private String ssn;
                    String getSsn() { return ssn; }
                    void setSsn(String value) { ssn = value; }
                        }
                        """));
        Compilation generated = compile(source("demo.GeneratedStateCustomer", """
                package demo;
                import io.github.ajaygodbole7.piitoken.annotation.*;
                @jakarta.persistence.Entity
                class GeneratedStateCustomer {
                    @jakarta.persistence.Id private long id;
                    @org.hibernate.annotations.Generated
                    @PII(id = "generated-state.ssn", kind = Kind.SSN)
                    private String ssn;
                    String getSsn() { return ssn; }
                    void setSsn(String value) { ssn = value; }
                }
                """));
        Compilation autoApplyConverter = compile(
                source("demo.AutoConverter", """
                        package demo;
                        @jakarta.persistence.Converter(autoApply = true)
                        class AutoConverter {}
                        """),
                validEntity("demo.AutoConvertedCustomer", "auto-converted.ssn"));

        assertThat(inheritance.errorMessages())
                .contains("PII012 protected entity inheritance is not supported");
        assertThat(propertyAccess.errorMessages())
                .contains("PII013 protected entities require field access; "
                        + "property-access @Id is not supported");
        assertThat(embeddedId.errorMessages())
                .contains("PII014 embedded or composite entity ids are not supported");
        assertThat(propertyEmbeddedId.errorMessages())
                .contains("PII014 embedded or composite entity ids are not supported");
        assertThat(converted.errorMessages())
                .contains("PII015 attribute converters on @PII fields are not supported");
        assertThat(groupedConverters.errorMessages())
                .contains("PII015 attribute converters on @PII fields are not supported");
        assertThat(immutable.errorMessages())
                .contains("PII016 generated or immutable @PII state is not supported");
        assertThat(generated.errorMessages())
                .contains("PII016 generated or immutable @PII state is not supported");
        assertThat(autoApplyConverter.errorMessages())
                .contains("PII015 attribute converters on @PII fields are not supported");
    }

    @Test
    void rejectsGeneratedTypeNameCollision() throws Exception {
        Compilation result = compile(
                source("demo.CustomerPiiRepositoryFragment", """
                        package demo;
                        interface CustomerPiiRepositoryFragment {}
                        """),
                validEntity("demo.Customer", "customer.ssn"));

        assertThat(result.success()).isFalse();
        assertThat(result.errorMessages()).contains(
                "PII011 generated @PII type name collides with an existing type");
    }

    private Compilation compile(Source... sources) throws Exception {
        return compile(List.of(new PiiProcessor()), sources);
    }

    private Compilation compile(List<? extends Processor> processors, Source... sources)
            throws Exception {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        Path sourceRoot = Files.createDirectories(temporary.resolve("source-" + System.nanoTime()));
        Path classes = Files.createDirectories(temporary.resolve("classes-" + System.nanoTime()));
        Path generated = Files.createDirectories(temporary.resolve("generated-" + System.nanoTime()));
        List<Path> sourceFiles = new ArrayList<>();
        List<Source> compilationSources = new ArrayList<>(List.of(repositorySupport()));
        compilationSources.addAll(List.of(sources));
        for (Source source : compilationSources) {
            Path file = sourceRoot.resolve(source.name().replace('.', '/') + ".java");
            Files.createDirectories(file.getParent());
            Files.writeString(file, source.content());
            sourceFiles.add(file);
        }

        var diagnostics = new javax.tools.DiagnosticCollector<JavaFileObject>();
        try (StandardJavaFileManager files = compiler.getStandardFileManager(
                diagnostics,
                Locale.ROOT,
                java.nio.charset.StandardCharsets.UTF_8)) {
            files.setLocationFromPaths(StandardLocation.CLASS_OUTPUT, List.of(classes));
            files.setLocationFromPaths(StandardLocation.SOURCE_OUTPUT, List.of(generated));
            Iterable<? extends JavaFileObject> units = files.getJavaFileObjectsFromPaths(sourceFiles);
            List<String> options = List.of(
                    "--release", "25",
                    "-classpath", System.getProperty("java.class.path"));
            JavaCompiler.CompilationTask task = compiler.getTask(
                    null,
                    files,
                    diagnostics,
                    options,
                    null,
                    units);
            task.setProcessors(processors);
            boolean success = task.call();
            List<String> errors = diagnostics.getDiagnostics().stream()
                    .filter(diagnostic -> diagnostic.getKind() == Diagnostic.Kind.ERROR)
                    .map(diagnostic -> diagnostic.getMessage(Locale.ROOT))
                    .toList();
            return new Compilation(success, classes, generated, errors);
        }
    }

    private static Source validEntity(String qualifiedName, String id) {
        int separator = qualifiedName.lastIndexOf('.');
        String packageName = qualifiedName.substring(0, separator);
        String simpleName = qualifiedName.substring(separator + 1);
        return source(qualifiedName, """
                package %s;
                import io.github.ajaygodbole7.piitoken.annotation.*;
                @jakarta.persistence.Entity
                class %s {
                    @jakarta.persistence.Id
                    private long id;
                    @PII(id = "%s", kind = Kind.SSN)
                    private String ssn;
                    String getSsn() { return ssn; }
                    void setSsn(String value) { ssn = value; }
                }
                """.formatted(packageName, simpleName, id));
    }

    private static Source[] repositorySupport() {
        return new Source[] {
            source("jakarta.persistence.Entity", """
                    package jakarta.persistence;
                    @java.lang.annotation.Retention(java.lang.annotation.RetentionPolicy.RUNTIME)
                    @java.lang.annotation.Target(java.lang.annotation.ElementType.TYPE)
                    public @interface Entity {}
                    """),
            source("jakarta.persistence.Id", """
                    package jakarta.persistence;
                    @java.lang.annotation.Retention(java.lang.annotation.RetentionPolicy.RUNTIME)
                    @java.lang.annotation.Target({java.lang.annotation.ElementType.FIELD,
                                                  java.lang.annotation.ElementType.METHOD})
                    public @interface Id {}
                    """),
            source("jakarta.persistence.IdClass", """
                    package jakarta.persistence;
                    @java.lang.annotation.Retention(java.lang.annotation.RetentionPolicy.RUNTIME)
                    @java.lang.annotation.Target(java.lang.annotation.ElementType.TYPE)
                    public @interface IdClass { Class<?> value(); }
                    """),
            source("jakarta.persistence.EmbeddedId", """
                    package jakarta.persistence;
                    @java.lang.annotation.Retention(java.lang.annotation.RetentionPolicy.RUNTIME)
                    @java.lang.annotation.Target({java.lang.annotation.ElementType.FIELD,
                                                  java.lang.annotation.ElementType.METHOD})
                    public @interface EmbeddedId {}
                    """),
            source("jakarta.persistence.Access", """
                    package jakarta.persistence;
                    @java.lang.annotation.Retention(java.lang.annotation.RetentionPolicy.RUNTIME)
                    @java.lang.annotation.Target({java.lang.annotation.ElementType.TYPE,
                                                  java.lang.annotation.ElementType.FIELD,
                                                  java.lang.annotation.ElementType.METHOD})
                    public @interface Access {}
                    """),
            source("jakarta.persistence.Convert", """
                    package jakarta.persistence;
                    @java.lang.annotation.Retention(java.lang.annotation.RetentionPolicy.RUNTIME)
                    @java.lang.annotation.Target({java.lang.annotation.ElementType.TYPE,
                                                  java.lang.annotation.ElementType.FIELD})
                    public @interface Convert {}
                    """),
            source("jakarta.persistence.Converts", """
                    package jakarta.persistence;
                    @java.lang.annotation.Retention(java.lang.annotation.RetentionPolicy.RUNTIME)
                    @java.lang.annotation.Target({java.lang.annotation.ElementType.TYPE,
                                                  java.lang.annotation.ElementType.FIELD})
                    public @interface Converts { Convert[] value(); }
                    """),
            source("jakarta.persistence.Converter", """
                    package jakarta.persistence;
                    @java.lang.annotation.Retention(java.lang.annotation.RetentionPolicy.RUNTIME)
                    @java.lang.annotation.Target(java.lang.annotation.ElementType.TYPE)
                    public @interface Converter { boolean autoApply() default false; }
                    """),
            source("org.hibernate.annotations.Immutable", """
                    package org.hibernate.annotations;
                    @java.lang.annotation.Retention(java.lang.annotation.RetentionPolicy.RUNTIME)
                    @java.lang.annotation.Target({java.lang.annotation.ElementType.TYPE,
                                                  java.lang.annotation.ElementType.FIELD})
                    public @interface Immutable {}
                    """),
            source("org.hibernate.annotations.Generated", """
                    package org.hibernate.annotations;
                    @java.lang.annotation.Retention(java.lang.annotation.RetentionPolicy.RUNTIME)
                    @java.lang.annotation.Target(java.lang.annotation.ElementType.FIELD)
                    public @interface Generated {}
                    """),
            source("jakarta.persistence.PersistenceContext", """
                    package jakarta.persistence;
                    @java.lang.annotation.Retention(java.lang.annotation.RetentionPolicy.RUNTIME)
                    @java.lang.annotation.Target(java.lang.annotation.ElementType.FIELD)
                    public @interface PersistenceContext {}
                    """),
            source("jakarta.persistence.EntityManager", """
                    package jakarta.persistence;
                    public interface EntityManager {
                        <T> T find(Class<T> type, Object id);
                        void flush();
                    }
                    """),
            source("org.springframework.transaction.annotation.Transactional", """
                    package org.springframework.transaction.annotation;
                    @java.lang.annotation.Retention(java.lang.annotation.RetentionPolicy.RUNTIME)
                    @java.lang.annotation.Target({java.lang.annotation.ElementType.METHOD,
                                                  java.lang.annotation.ElementType.TYPE})
                    public @interface Transactional {}
                    """),
            source(
                    "io.github.ajaygodbole7.piitoken.protocol.GeneratedPiiJpaOperations",
                    """
                    package io.github.ajaygodbole7.piitoken.protocol;
                    public final class GeneratedPiiJpaOperations {
                        public <T> boolean existsBy(
                                jakarta.persistence.EntityManager entityManager,
                                Class<T> type, String id, String field, String candidate) {
                            return false;
                        }
                        public <T> java.util.List<T> findAllBy(
                                jakarta.persistence.EntityManager entityManager,
                                Class<T> type, String id, String field, String candidate) {
                            return java.util.List.of();
                        }
                        public <T> boolean matches(
                                jakarta.persistence.EntityManager entityManager,
                                Class<T> type, Object entityId, String id, String field,
                                String candidate,
                                java.util.function.Function<? super T, String> reader) {
                            return false;
                        }
                        public <T> boolean replace(
                                jakarta.persistence.EntityManager entityManager,
                                Class<T> type, Object entityId, String id, String field,
                                String value,
                                java.util.function.BiConsumer<? super T, String> writer) {
                            return false;
                        }
                    }
                    """)
        };
    }

    private static Source source(String name, String content) {
        return new Source(name, content);
    }

    private record Source(String name, String content) {
    }

    private record Compilation(
            boolean success,
            Path classes,
            Path generatedSources,
            List<String> errorMessages) {
    }

    private static final class LateEntityProcessor extends AbstractProcessor {

        private boolean generated;

        @Override
        public Set<String> getSupportedAnnotationTypes() {
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
            if (generated || roundEnvironment.processingOver()) {
                return false;
            }
            generated = true;
            try (var writer = processingEnv.getFiler()
                    .createSourceFile("demo.GeneratedCustomer")
                    .openWriter()) {
                writer.write("""
                        package demo;
                        import io.github.ajaygodbole7.piitoken.annotation.*;
                        @jakarta.persistence.Entity
                        class GeneratedCustomer {
                            @jakarta.persistence.Id
                            private long id;
                            @PII(id = "generated.ssn", kind = Kind.SSN)
                            private String ssn;
                            String getSsn() { return ssn; }
                            void setSsn(String value) { ssn = value; }
                        }
                        """);
            }
            catch (java.io.IOException exception) {
                throw new IllegalStateException(exception);
            }
            return false;
        }
    }
}
