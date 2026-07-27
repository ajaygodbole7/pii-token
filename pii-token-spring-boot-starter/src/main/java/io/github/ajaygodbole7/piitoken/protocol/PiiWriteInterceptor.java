package io.github.ajaygodbole7.piitoken.protocol;

import io.github.ajaygodbole7.piitoken.annotation.Mask;
import io.github.ajaygodbole7.piitoken.descriptor.PiiFieldAccess;
import io.github.ajaygodbole7.piitoken.descriptor.PiiFieldDescriptor;
import io.github.ajaygodbole7.piitoken.provider.TokenMacProvider;
import io.github.ajaygodbole7.piitoken.runtime.ApprovedRuntimePolicy;
import io.github.ajaygodbole7.piitoken.runtime.GeneratedPiiModel;
import io.github.ajaygodbole7.piitoken.runtime.PiiRuntimeGate;
import org.hibernate.Interceptor;
import org.hibernate.type.Type;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Internal Hibernate write-path bridge. All generated field transforms are
 * staged before any entity or Hibernate state mutation.
 */
public final class PiiWriteInterceptor implements Interceptor {

    private final GeneratedPiiModel generatedModel;
    private final PiiRuntimeGate runtimeGate;
    private final P1N1TokenEngine tokenEngine;

    public PiiWriteInterceptor(
            GeneratedPiiModel generatedModel,
            PiiRuntimeGate runtimeGate,
            TokenMacProvider tokenMacProvider) {
        this.generatedModel = Objects.requireNonNull(generatedModel, "generatedModel");
        this.runtimeGate = Objects.requireNonNull(runtimeGate, "runtimeGate");
        this.tokenEngine = new P1N1TokenEngine(
                Objects.requireNonNull(tokenMacProvider, "tokenMacProvider"),
                new SecureSaltSource());
    }

    @Override
    public boolean onLoad(
            Object entity,
            Object id,
            Object[] state,
            String[] propertyNames,
            Type[] types) {
        List<PiiFieldAccess<?>> fields = generatedModel.fieldsFor(entity);
        if (fields.isEmpty()) {
            return false;
        }
        ApprovedRuntimePolicy policy = runtimeGate.require();
        List<FieldState> fieldStates = resolveFieldStates(
                fields,
                state,
                null,
                propertyNames,
                false);
        for (FieldState fieldState : fieldStates) {
            validateLoadedState(policy, fieldState);
        }
        return false;
    }

    @Override
    public boolean onPersist(
            Object entity,
            Object id,
            Object[] state,
            String[] propertyNames,
            Type[] types) {
        List<PiiFieldAccess<?>> fields = generatedModel.fieldsFor(entity);
        if (fields.isEmpty()) {
            return false;
        }
        ApprovedRuntimePolicy policy = runtimeGate.require();
        List<FieldState> fieldStates = resolveFieldStates(
                fields,
                state,
                null,
                propertyNames,
                false);
        List<StagedMutation> staged = new ArrayList<>(fieldStates.size());
        for (FieldState fieldState : fieldStates) {
            staged.add(new StagedMutation(
                    fieldState,
                    tokenEngine.protect(
                            context(policy, fieldState.access().descriptor()),
                            fieldState.value())));
        }
        apply(entity, state, staged);
        return true;
    }

    @Override
    public boolean onFlushDirty(
            Object entity,
            Object id,
            Object[] currentState,
            Object[] previousState,
            String[] propertyNames,
            Type[] types) {
        List<PiiFieldAccess<?>> fields = generatedModel.fieldsFor(entity);
        if (fields.isEmpty()) {
            return false;
        }
        ApprovedRuntimePolicy policy = runtimeGate.require();
        if (previousState == null) {
            throw failure(ProtocolReason.PERSISTENCE_STATE_INVALID);
        }
        List<FieldState> fieldStates = resolveFieldStates(
                fields,
                currentState,
                previousState,
                propertyNames,
                true);
        List<StagedMutation> staged = new ArrayList<>();
        for (FieldState fieldState : fieldStates) {
            if (fieldState.suffixDirty() && !fieldState.valueDirty()) {
                throw failure(ProtocolReason.INDEPENDENT_SUFFIX_MUTATION);
            }
            if (fieldState.valueDirty()) {
                staged.add(new StagedMutation(
                        fieldState,
                        tokenEngine.protect(
                                context(policy, fieldState.access().descriptor()),
                                fieldState.value())));
            }
        }
        if (staged.isEmpty()) {
            return false;
        }
        apply(entity, currentState, staged);
        return true;
    }

    private static List<FieldState> resolveFieldStates(
            List<PiiFieldAccess<?>> fields,
            Object[] currentState,
            Object[] previousState,
            String[] propertyNames,
            boolean dirtyCheck) {
        if (currentState == null || propertyNames == null
                || currentState.length != propertyNames.length
                || (dirtyCheck && previousState.length != currentState.length)) {
            throw failure(ProtocolReason.PERSISTENCE_STATE_INVALID);
        }
        List<FieldState> states = new ArrayList<>(fields.size());
        for (PiiFieldAccess<?> access : fields) {
            PiiFieldDescriptor descriptor = access.descriptor();
            int valueIndex = indexOf(propertyNames, descriptor.fieldName());
            int suffixIndex = descriptor.mask() == Mask.LAST4
                    ? indexOf(propertyNames, descriptor.fieldName() + "Last4")
                    : -1;
            Object value = currentState[valueIndex];
            if (value != null && !(value instanceof String)) {
                throw failure(ProtocolReason.PERSISTENCE_STATE_INVALID);
            }
            Object suffix = suffixIndex >= 0 ? currentState[suffixIndex] : null;
            if (suffix != null && !(suffix instanceof String)) {
                throw failure(ProtocolReason.PERSISTENCE_STATE_INVALID);
            }
            boolean valueDirty = dirtyCheck
                    && !Objects.equals(value, previousState[valueIndex]);
            boolean suffixDirty = dirtyCheck
                    && suffixIndex >= 0
                    && !Objects.equals(
                    currentState[suffixIndex],
                    previousState[suffixIndex]);
            states.add(new FieldState(
                    access,
                    valueIndex,
                    suffixIndex,
                    (String) value,
                    (String) suffix,
                    valueDirty,
                    suffixDirty));
        }
        return states;
    }

    private static void validateLoadedState(
            ApprovedRuntimePolicy policy,
            FieldState fieldState) {
        String token = fieldState.value();
        String suffix = fieldState.suffix();
        if (token == null) {
            if (suffix != null) {
                throw failure(ProtocolReason.INVALID_STORED_SUFFIX);
            }
            return;
        }

        String logicalVersion = fieldState.access().descriptor().searchable()
                ? TokenCodec.parseSearchable(token).keyVersion()
                : TokenCodec.parseMatchOnly(token).keyVersion();
        if (!policy.liveKeyVersions().contains(logicalVersion)) {
            throw failure(ProtocolReason.UNKNOWN_KEY_VERSION);
        }

        if (fieldState.access().descriptor().mask() == Mask.LAST4
                && !isLast4(suffix)) {
            throw failure(ProtocolReason.INVALID_STORED_SUFFIX);
        }
    }

    private static boolean isLast4(String suffix) {
        if (suffix == null || suffix.length() != 4) {
            return false;
        }
        for (int index = 0; index < suffix.length(); index++) {
            char digit = suffix.charAt(index);
            if (digit < '0' || digit > '9') {
                return false;
            }
        }
        return true;
    }

    private static void apply(
            Object entity,
            Object[] state,
            List<StagedMutation> stagedMutations) {
        for (StagedMutation mutation : stagedMutations) {
            FieldState field = mutation.field();
            StagedProtection protection = mutation.protection();
            state[field.valueIndex()] = protection.token();
            access(field.access()).writeValue(entity, protection.token());
            if (field.suffixIndex() >= 0) {
                state[field.suffixIndex()] = protection.last4();
                access(field.access()).writeLast4(entity, protection.last4());
            }
        }
    }

    private static TokenContext context(
            ApprovedRuntimePolicy policy,
            PiiFieldDescriptor descriptor) {
        return new TokenContext(
                policy.applicationNamespace(),
                descriptor,
                policy.currentWriteVersion(),
                policy.liveKeyVersions());
    }

    private static int indexOf(String[] propertyNames, String target) {
        for (int index = 0; index < propertyNames.length; index++) {
            if (target.equals(propertyNames[index])) {
                return index;
            }
        }
        throw failure(ProtocolReason.PERSISTENCE_STATE_INVALID);
    }

    @SuppressWarnings("unchecked")
    private static PiiFieldAccess<Object> access(PiiFieldAccess<?> field) {
        return (PiiFieldAccess<Object>) field;
    }

    private static PiiProtocolException failure(ProtocolReason reason) {
        return new PiiProtocolException(reason);
    }

    private record FieldState(
            PiiFieldAccess<?> access,
            int valueIndex,
            int suffixIndex,
            String value,
            String suffix,
            boolean valueDirty,
            boolean suffixDirty) {

        @Override
        public String toString() {
            return "FieldState[REDACTED]";
        }
    }

    private record StagedMutation(
            FieldState field,
            StagedProtection protection) {

        @Override
        public String toString() {
            return "StagedMutation[REDACTED]";
        }
    }
}
