package io.github.ajaygodbole7.piitoken.descriptor;

import io.github.ajaygodbole7.piitoken.annotation.Kind;
import io.github.ajaygodbole7.piitoken.annotation.Mask;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Frozen p1/n1 six-field descriptor manifest codec.
 */
public final class DescriptorManifestCodec {

    private static final Pattern ID = Pattern.compile("[a-z0-9.-]{3,64}");
    private static final Pattern ENTITY_CLASS = Pattern.compile(
            "[A-Za-z_$][A-Za-z0-9_$]*(?:\\.[A-Za-z_$][A-Za-z0-9_$]*)*");
    private static final Pattern FIELD_NAME = Pattern.compile("[A-Za-z_$][A-Za-z0-9_$]*");
    private static final HexFormat HEX = HexFormat.of();

    private DescriptorManifestCodec() {
    }

    public static String encode(List<PiiFieldDescriptor> descriptors) {
        Objects.requireNonNull(descriptors, "descriptors");
        List<PiiFieldDescriptor> canonical = new ArrayList<>(descriptors);
        Set<String> ids = new HashSet<>();
        for (PiiFieldDescriptor descriptor : canonical) {
            validateDescriptor(descriptor);
            if (!ids.add(descriptor.id())) {
                throw invalidManifest();
            }
        }
        canonical.sort(Comparator.comparing(PiiFieldDescriptor::id));

        StringBuilder manifest = new StringBuilder();
        for (int index = 0; index < canonical.size(); index++) {
            if (index > 0) {
                manifest.append('\n');
            }
            PiiFieldDescriptor descriptor = canonical.get(index);
            manifest.append(descriptor.id()).append('|')
                    .append(descriptor.kind().name()).append('|')
                    .append(descriptor.searchable()).append('|')
                    .append(descriptor.mask().name()).append('|')
                    .append(descriptor.entityClassName()).append('|')
                    .append(descriptor.fieldName());
        }
        return manifest.toString();
    }

    public static List<PiiFieldDescriptor> decode(String manifest) {
        Objects.requireNonNull(manifest, "manifest");
        if (manifest.isEmpty()) {
            return List.of();
        }
        if (manifest.indexOf('\r') >= 0
                || manifest.startsWith("\n")
                || manifest.endsWith("\n")
                || manifest.contains("\n\n")) {
            throw invalidManifest();
        }

        List<PiiFieldDescriptor> descriptors = new ArrayList<>();
        String previousId = null;
        for (String line : manifest.split("\n", -1)) {
            String[] fields = line.split("\\|", -1);
            if (fields.length != 6) {
                throw invalidManifest();
            }
            boolean searchable;
            if ("true".equals(fields[2])) {
                searchable = true;
            }
            else if ("false".equals(fields[2])) {
                searchable = false;
            }
            else {
                throw invalidManifest();
            }

            PiiFieldDescriptor descriptor;
            try {
                descriptor = new PiiFieldDescriptor(
                        fields[0],
                        Kind.valueOf(fields[1]),
                        searchable,
                        Mask.valueOf(fields[3]),
                        fields[4],
                        fields[5]);
            }
            catch (IllegalArgumentException | NullPointerException exception) {
                throw invalidManifest();
            }
            validateDescriptor(descriptor);
            if (previousId != null && previousId.compareTo(descriptor.id()) >= 0) {
                throw invalidManifest();
            }
            previousId = descriptor.id();
            descriptors.add(descriptor);
        }
        if (!encode(descriptors).equals(manifest)) {
            throw invalidManifest();
        }
        return List.copyOf(descriptors);
    }

    public static String fingerprint(String manifest) {
        Objects.requireNonNull(manifest, "manifest");
        try {
            return HEX.formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(manifest.getBytes(StandardCharsets.UTF_8)));
        }
        catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA_256_UNAVAILABLE", impossible);
        }
    }

    private static void validateDescriptor(PiiFieldDescriptor descriptor) {
        if (descriptor == null
                || !ID.matcher(descriptor.id()).matches()
                || !ENTITY_CLASS.matcher(descriptor.entityClassName()).matches()
                || !FIELD_NAME.matcher(descriptor.fieldName()).matches()) {
            throw invalidManifest();
        }
    }

    private static IllegalArgumentException invalidManifest() {
        return new IllegalArgumentException("INVALID_DESCRIPTOR_MANIFEST");
    }
}
