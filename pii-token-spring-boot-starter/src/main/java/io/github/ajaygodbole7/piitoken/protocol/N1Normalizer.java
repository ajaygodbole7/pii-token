package io.github.ajaygodbole7.piitoken.protocol;

import io.github.ajaygodbole7.piitoken.annotation.Kind;

import java.util.Objects;
import java.util.regex.Pattern;

final class N1Normalizer {

    private static final Pattern SSN_DIGITS = Pattern.compile("[0-9]{9}");
    private static final Pattern SSN_FORMATTED = Pattern.compile("[0-9]{3}-[0-9]{2}-[0-9]{4}");
    private static final Pattern PAN_DIGITS = Pattern.compile("[0-9]{12,19}");
    private static final Pattern GROUP_OF_FOUR = Pattern.compile("[0-9]{4}");
    private static final Pattern FINAL_GROUP = Pattern.compile("[0-9]{1,4}");

    private N1Normalizer() {
    }

    static NormalizedValue normalize(Kind kind, String presented) {
        Objects.requireNonNull(kind, "kind");
        if (presented == null) {
            throw invalidValue();
        }
        return switch (kind) {
            case SSN -> normalizeSsn(presented);
            case PAN -> normalizePan(presented);
        };
    }

    private static NormalizedValue normalizeSsn(String presented) {
        if (SSN_DIGITS.matcher(presented).matches()) {
            return NormalizedValue.of(presented);
        }
        if (SSN_FORMATTED.matcher(presented).matches()) {
            return NormalizedValue.of(presented.substring(0, 3)
                    + presented.substring(4, 6)
                    + presented.substring(7));
        }
        throw invalidValue();
    }

    private static NormalizedValue normalizePan(String presented) {
        String normalized;
        if (PAN_DIGITS.matcher(presented).matches()) {
            normalized = presented;
        }
        else {
            normalized = normalizeGroupedPan(presented);
        }
        if (!luhnValid(normalized)) {
            throw invalidValue();
        }
        return NormalizedValue.of(normalized);
    }

    private static String normalizeGroupedPan(String presented) {
        boolean hasSpace = presented.indexOf(' ') >= 0;
        boolean hasHyphen = presented.indexOf('-') >= 0;
        if (hasSpace == hasHyphen) {
            throw invalidValue();
        }

        String separator = hasSpace ? " " : "-";
        String[] groups = presented.split(Pattern.quote(separator), -1);
        if (groups.length < 3 || groups.length > 5) {
            throw invalidValue();
        }
        for (int index = 0; index < groups.length - 1; index++) {
            if (!GROUP_OF_FOUR.matcher(groups[index]).matches()) {
                throw invalidValue();
            }
        }
        if (!FINAL_GROUP.matcher(groups[groups.length - 1]).matches()) {
            throw invalidValue();
        }

        String normalized = String.join("", groups);
        if (!PAN_DIGITS.matcher(normalized).matches()) {
            throw invalidValue();
        }
        return normalized;
    }

    private static boolean luhnValid(String digits) {
        int total = 0;
        int position = 0;
        for (int index = digits.length() - 1; index >= 0; index--, position++) {
            int digit = digits.charAt(index) - '0';
            if ((position & 1) == 1) {
                digit *= 2;
                if (digit > 9) {
                    digit -= 9;
                }
            }
            total += digit;
        }
        return total % 10 == 0;
    }

    private static PiiProtocolException invalidValue() {
        return new PiiProtocolException(ProtocolReason.INVALID_VALUE);
    }
}
