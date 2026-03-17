package io.authgate.domain.service;

import io.authgate.domain.model.DelegationContext;
import io.authgate.domain.model.ValidatedToken;

import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/**
 * Domain service: evaluates whether a delegation context can be established.
 */
public final class DelegationPolicy {

    private final String requiredScope;
    private final String actingSubjectHeaderName;

    public DelegationPolicy(String requiredScope, String actingSubjectHeaderName) {
        this.requiredScope = Objects.requireNonNull(requiredScope);
        this.actingSubjectHeaderName = Objects.requireNonNull(actingSubjectHeaderName);
    }

    public DelegationPolicy() {
        this("service:delegate", "X-Acting-Subject");
    }

    public void describeHeaderNameTo(Consumer<String> consumer) {
        consumer.accept(actingSubjectHeaderName);
    }

    public Optional<DelegationContext> evaluate(ValidatedToken token, String onBehalfOfHeader) {
        Objects.requireNonNull(token);

        if (!token.hasScope(requiredScope)) {
            return Optional.empty();
        }
        if (onBehalfOfHeader == null || onBehalfOfHeader.isBlank()) {
            return Optional.empty();
        }

        var subject = new AtomicReference<String>();
        token.describeSubjectTo(subject::set);

        return Optional.of(new DelegationContext(subject.get(), onBehalfOfHeader.trim()));
    }
}
