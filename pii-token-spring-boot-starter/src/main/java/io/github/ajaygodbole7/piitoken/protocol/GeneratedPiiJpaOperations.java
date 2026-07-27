package io.github.ajaygodbole7.piitoken.protocol;

import io.github.ajaygodbole7.piitoken.descriptor.PiiFieldDescriptor;
import io.github.ajaygodbole7.piitoken.provider.TokenMacProvider;
import io.github.ajaygodbole7.piitoken.runtime.ApprovedRuntimePolicy;
import io.github.ajaygodbole7.piitoken.runtime.PiiRuntimeGate;
import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Root;

import java.util.List;
import java.util.Objects;
import java.util.function.BiConsumer;
import java.util.function.Function;

/**
 * Internal semantic bridge used only by annotation-processor generated
 * repository fragments.
 *
 * <p>The class is public solely because generated code lives in the consumer's
 * entity package. It deliberately exposes no raw token-generation operation.
 */
public final class GeneratedPiiJpaOperations {

    private final PiiRuntimeGate runtimeGate;
    private final P1N1TokenEngine tokenEngine;

    public GeneratedPiiJpaOperations(
            PiiRuntimeGate runtimeGate,
            TokenMacProvider tokenMacProvider) {
        this.runtimeGate = Objects.requireNonNull(runtimeGate, "runtimeGate");
        this.tokenEngine = new P1N1TokenEngine(
                Objects.requireNonNull(tokenMacProvider, "tokenMacProvider"),
                new SecureSaltSource());
    }

    public <T> boolean existsBy(
            EntityManager entityManager,
            Class<T> entityType,
            String fieldId,
            String fieldName,
            String candidate) {
        TokenContext context = searchableContext(entityType, fieldId, fieldName);
        List<String> tokens = searchTokens(context, candidate);
        CriteriaBuilder builder = entityManager.getCriteriaBuilder();
        CriteriaQuery<Integer> criteria = builder.createQuery(Integer.class);
        Root<T> root = criteria.from(entityType);
        criteria.select(builder.literal(1))
                .where(root.<String>get(fieldName).in(tokens));
        TypedQuery<Integer> query = entityManager.createQuery(criteria);
        return !query.setMaxResults(1).getResultList().isEmpty();
    }

    public <T> List<T> findAllBy(
            EntityManager entityManager,
            Class<T> entityType,
            String fieldId,
            String fieldName,
            String candidate) {
        TokenContext context = searchableContext(entityType, fieldId, fieldName);
        List<String> tokens = searchTokens(context, candidate);
        CriteriaBuilder builder = entityManager.getCriteriaBuilder();
        CriteriaQuery<T> criteria = builder.createQuery(entityType);
        Root<T> root = criteria.from(entityType);
        criteria.select(root)
                .where(root.<String>get(fieldName).in(tokens));
        return entityManager.createQuery(criteria).getResultList();
    }

    public <T> boolean matches(
            EntityManager entityManager,
            Class<T> entityType,
            Object entityId,
            String fieldId,
            String fieldName,
            String candidate,
            Function<? super T, String> valueReader) {
        TokenContext context = context(entityType, fieldId, fieldName, false);
        T entity = entityManager.find(entityType, entityId);
        if (entity == null) {
            return false;
        }
        String storedToken = valueReader.apply(entity);
        return storedToken != null
                && tokenEngine.verify(context, candidate, storedToken) == MatchResult.MATCH;
    }

    public <T> boolean replace(
            EntityManager entityManager,
            Class<T> entityType,
            Object entityId,
            String fieldId,
            String fieldName,
            String value,
            BiConsumer<? super T, String> valueWriter) {
        context(entityType, fieldId, fieldName, false);
        T entity = entityManager.find(entityType, entityId);
        if (entity == null) {
            return false;
        }
        valueWriter.accept(entity, value);
        return true;
    }

    private <T> TokenContext searchableContext(
            Class<T> entityType,
            String fieldId,
            String fieldName) {
        return context(entityType, fieldId, fieldName, true);
    }

    private <T> TokenContext context(
            Class<T> entityType,
            String fieldId,
            String fieldName,
            boolean searchableRequired) {
        ApprovedRuntimePolicy policy = runtimeGate.require();
        Objects.requireNonNull(entityType, "entityType");
        PiiFieldDescriptor descriptor = null;
        for (PiiFieldDescriptor candidate : policy.descriptors()) {
            if (candidate.id().equals(fieldId)) {
                if (descriptor != null) {
                    throw new PiiProtocolException(ProtocolReason.PROVIDER_POLICY_MISMATCH);
                }
                descriptor = candidate;
            }
        }
        if (descriptor == null
                || !descriptor.entityClassName().equals(entityType.getName())
                || !descriptor.fieldName().equals(fieldName)) {
            throw new PiiProtocolException(ProtocolReason.PROVIDER_POLICY_MISMATCH);
        }
        if (searchableRequired && !descriptor.searchable()) {
            throw new PiiProtocolException(ProtocolReason.WRONG_OPERATION);
        }
        return new TokenContext(
                policy.applicationNamespace(),
                descriptor,
                policy.currentWriteVersion(),
                policy.liveKeyVersions());
    }

    private List<String> searchTokens(TokenContext context, String candidate) {
        return tokenEngine.searchTokens(context, candidate)
                .candidates()
                .stream()
                .map(SearchTokenCandidate::token)
                .toList();
    }
}
