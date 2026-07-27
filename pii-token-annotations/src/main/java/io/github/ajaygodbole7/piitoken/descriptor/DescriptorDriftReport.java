package io.github.ajaygodbole7.piitoken.descriptor;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;

/**
 * Content-safe descriptor metadata diff used by startup and offline diagnostics.
 */
public final class DescriptorDriftReport {

    private final String approvedManifest;
    private final String compiledManifest;
    private final List<Change> changes;

    private DescriptorDriftReport(
            String approvedManifest,
            String compiledManifest,
            List<Change> changes) {
        this.approvedManifest = approvedManifest;
        this.compiledManifest = compiledManifest;
        this.changes = List.copyOf(changes);
    }

    public static DescriptorDriftReport compare(
            String approvedManifest,
            String compiledManifest) {
        Objects.requireNonNull(approvedManifest, "approvedManifest");
        Objects.requireNonNull(compiledManifest, "compiledManifest");
        List<PiiFieldDescriptor> approved = DescriptorManifestCodec.decode(approvedManifest);
        List<PiiFieldDescriptor> compiled = DescriptorManifestCodec.decode(compiledManifest);

        Map<String, PiiFieldDescriptor> approvedById = byId(approved);
        Map<String, PiiFieldDescriptor> compiledById = byId(compiled);
        Set<String> unmatchedApproved = new LinkedHashSet<>(approvedById.keySet());
        Set<String> unmatchedCompiled = new LinkedHashSet<>(compiledById.keySet());
        List<Change> changes = new ArrayList<>();

        for (String id : approvedById.keySet()) {
            PiiFieldDescriptor before = approvedById.get(id);
            PiiFieldDescriptor after = compiledById.get(id);
            if (after == null) {
                continue;
            }
            unmatchedApproved.remove(id);
            unmatchedCompiled.remove(id);
            List<AttributeDiff> attributes = attributeDiffs(before, after);
            if (!attributes.isEmpty()) {
                changes.add(altered(before, after, attributes));
            }
        }

        pairProvableIdChanges(
                approvedById,
                compiledById,
                unmatchedApproved,
                unmatchedCompiled,
                changes);

        for (String id : unmatchedApproved) {
            PiiFieldDescriptor field = approvedById.get(id);
            changes.add(new Change(
                    ChangeType.REMOVED,
                    id,
                    id,
                    field,
                    null,
                    List.of(),
                    List.of(Classification.REMOVED_FIELD_SCHEMA_APPROVAL)));
        }
        for (String id : unmatchedCompiled) {
            PiiFieldDescriptor field = compiledById.get(id);
            changes.add(new Change(
                    ChangeType.ADDED,
                    id,
                    id,
                    null,
                    field,
                    List.of(),
                    List.of(Classification.NEW_FIELD_SCHEMA_APPROVAL)));
        }
        changes.sort(Comparator
                .comparing(Change::displayId)
                .thenComparing(Change::type));
        return new DescriptorDriftReport(approvedManifest, compiledManifest, changes);
    }

    public boolean hasChanges() {
        return !changes.isEmpty();
    }

    public List<String> changedFieldBlockIds() {
        return changes.stream()
                .filter(change -> change.compiled() != null)
                .map(change -> change.compiled().id())
                .distinct()
                .sorted()
                .toList();
    }

    public boolean hasTokenDomainChange() {
        return changes.stream()
                .anyMatch(change -> change.classifications()
                        .contains(Classification.TOKEN_DOMAIN_CHANGE));
    }

    public String render(String approvedFingerprint) {
        String expectedApproved = DescriptorManifestCodec.fingerprint(approvedManifest);
        if (!expectedApproved.equals(approvedFingerprint)) {
            throw new IllegalArgumentException("APPROVED_FINGERPRINT_MISMATCH");
        }
        String compiledFingerprint = DescriptorManifestCodec.fingerprint(compiledManifest);
        StringBuilder output = new StringBuilder();
        output.append("approved_fingerprint=")
                .append(approvedFingerprint)
                .append('\n')
                .append("compiled_fingerprint=")
                .append(compiledFingerprint)
                .append('\n')
                .append("changes:\n");
        for (Change change : changes) {
            renderChange(output, change);
        }
        output.append("generated_artifacts:\n")
                .append("- META-INF/pii/descriptor-manifest.txt\n")
                .append("- META-INF/pii/descriptor-fingerprint.txt\n")
                .append("- META-INF/pii/owner-migration-template.sql\n");
        for (String id : changedFieldBlockIds()) {
            output.append("- ")
                    .append(OwnerMigrationArtifacts.fieldBlockResource(id))
                    .append(" [")
                    .append(id)
                    .append("]\n");
        }
        if (hasTokenDomainChange()) {
            output.append("warning=TOKEN_DOMAIN_CHANGE requires recollection/new namespace; ")
                    .append("the registry UPDATE alone is unsafe\n");
        }
        output.append("proposed_policy_update:\n")
                .append(OwnerMigrationArtifacts.guardedPolicyUpdate(
                        compiledManifest,
                        approvedFingerprint));
        return output.toString();
    }

    private static Map<String, PiiFieldDescriptor> byId(List<PiiFieldDescriptor> fields) {
        Map<String, PiiFieldDescriptor> byId = new TreeMap<>();
        for (PiiFieldDescriptor field : fields) {
            byId.put(field.id(), field);
        }
        return byId;
    }

    private static void pairProvableIdChanges(
            Map<String, PiiFieldDescriptor> approvedById,
            Map<String, PiiFieldDescriptor> compiledById,
            Set<String> unmatchedApproved,
            Set<String> unmatchedCompiled,
            List<Change> changes) {
        Map<Location, List<PiiFieldDescriptor>> approvedByLocation =
                byLocation(approvedById, unmatchedApproved);
        Map<Location, List<PiiFieldDescriptor>> compiledByLocation =
                byLocation(compiledById, unmatchedCompiled);
        for (Map.Entry<Location, List<PiiFieldDescriptor>> entry
                : approvedByLocation.entrySet()) {
            List<PiiFieldDescriptor> beforeCandidates = entry.getValue();
            List<PiiFieldDescriptor> afterCandidates = compiledByLocation.get(entry.getKey());
            if (beforeCandidates.size() != 1
                    || afterCandidates == null
                    || afterCandidates.size() != 1) {
                continue;
            }
            PiiFieldDescriptor before = beforeCandidates.getFirst();
            PiiFieldDescriptor after = afterCandidates.getFirst();
            unmatchedApproved.remove(before.id());
            unmatchedCompiled.remove(after.id());
            List<AttributeDiff> attributes = new ArrayList<>();
            attributes.add(new AttributeDiff("id", before.id(), after.id()));
            attributes.addAll(attributeDiffs(before, after));
            changes.add(altered(before, after, attributes));
        }
    }

    private static Map<Location, List<PiiFieldDescriptor>> byLocation(
            Map<String, PiiFieldDescriptor> byId,
            Set<String> ids) {
        Map<Location, List<PiiFieldDescriptor>> byLocation = new LinkedHashMap<>();
        for (String id : ids) {
            PiiFieldDescriptor field = byId.get(id);
            byLocation.computeIfAbsent(
                            new Location(field.entityClassName(), field.fieldName()),
                            ignored -> new ArrayList<>())
                    .add(field);
        }
        return byLocation;
    }

    private static Change altered(
            PiiFieldDescriptor before,
            PiiFieldDescriptor after,
            List<AttributeDiff> attributes) {
        EnumSet<Classification> classifications = EnumSet.noneOf(Classification.class);
        for (AttributeDiff attribute : attributes) {
            switch (attribute.attribute()) {
                case "id", "kind", "searchable" ->
                        classifications.add(Classification.TOKEN_DOMAIN_CHANGE);
                case "entity", "field" ->
                        classifications.add(Classification.COORDINATED_MAPPING_MIGRATION);
                case "mask" ->
                        classifications.add(Classification.FORWARD_ONLY_MASK_CHANGE);
                default -> throw new IllegalStateException("UNKNOWN_DESCRIPTOR_ATTRIBUTE");
            }
        }
        return new Change(
                ChangeType.ALTERED,
                before.id(),
                after.id(),
                before,
                after,
                List.copyOf(attributes),
                List.copyOf(classifications));
    }

    private static List<AttributeDiff> attributeDiffs(
            PiiFieldDescriptor before,
            PiiFieldDescriptor after) {
        List<AttributeDiff> attributes = new ArrayList<>();
        addIfChanged(attributes, "kind", before.kind().name(), after.kind().name());
        addIfChanged(
                attributes,
                "searchable",
                Boolean.toString(before.searchable()),
                Boolean.toString(after.searchable()));
        addIfChanged(attributes, "mask", before.mask().name(), after.mask().name());
        addIfChanged(
                attributes,
                "entity",
                before.entityClassName(),
                after.entityClassName());
        addIfChanged(attributes, "field", before.fieldName(), after.fieldName());
        return attributes;
    }

    private static void addIfChanged(
            List<AttributeDiff> attributes,
            String attribute,
            String before,
            String after) {
        if (!before.equals(after)) {
            attributes.add(new AttributeDiff(attribute, before, after));
        }
    }

    private static void renderChange(StringBuilder output, Change change) {
        output.append("- ")
                .append(change.type())
                .append(' ')
                .append(change.displayId())
                .append('\n')
                .append("  classifications=")
                .append(String.join(
                        ",",
                        change.classifications().stream().map(Enum::name).toList()))
                .append('\n');
        if (change.type() == ChangeType.ADDED) {
            output.append("  compiled=")
                    .append(summary(change.compiled()))
                    .append('\n');
        }
        else if (change.type() == ChangeType.REMOVED) {
            output.append("  approved=")
                    .append(summary(change.approved()))
                    .append('\n');
        }
        else {
            output.append("  attributes:\n");
            for (AttributeDiff attribute : change.attributes()) {
                output.append("  - ")
                        .append(attribute.attribute())
                        .append(": ")
                        .append(attribute.approved())
                        .append(" -> ")
                        .append(attribute.compiled())
                        .append('\n');
            }
        }
        if (change.compiled() != null) {
            output.append("  ddl_block=")
                    .append(OwnerMigrationArtifacts.fieldBlockResource(
                            change.compiled().id()))
                    .append('\n');
        }
    }

    private static String summary(PiiFieldDescriptor field) {
        return "kind=" + field.kind().name()
                + ",searchable=" + field.searchable()
                + ",mask=" + field.mask().name()
                + ",entity=" + field.entityClassName()
                + ",field=" + field.fieldName();
    }

    private enum ChangeType {
        ADDED,
        REMOVED,
        ALTERED
    }

    private enum Classification {
        TOKEN_DOMAIN_CHANGE,
        NEW_FIELD_SCHEMA_APPROVAL,
        REMOVED_FIELD_SCHEMA_APPROVAL,
        COORDINATED_MAPPING_MIGRATION,
        FORWARD_ONLY_MASK_CHANGE
    }

    private record AttributeDiff(
            String attribute,
            String approved,
            String compiled) {
    }

    private record Change(
            ChangeType type,
            String approvedId,
            String compiledId,
            PiiFieldDescriptor approved,
            PiiFieldDescriptor compiled,
            List<AttributeDiff> attributes,
            List<Classification> classifications) {

        String displayId() {
            return approvedId.equals(compiledId)
                    ? approvedId
                    : approvedId + " -> " + compiledId;
        }
    }

    private record Location(String entity, String field) {
    }
}
