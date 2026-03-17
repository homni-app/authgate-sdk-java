package io.authgate.domain.model;

import java.util.Objects;
import java.util.function.Consumer;

/**
 * Verified delegation context.
 *
 * <p>Created only when:
 * <ol>
 *   <li>Caller token contains the required delegation scope</li>
 *   <li>Request includes the acting-subject header</li>
 * </ol>
 * If either fails — empty. Safe by default.</p>
 */
public final class DelegationContext {

    private final String serviceSubject;
    private final String actingOnBehalfOfSubject;

    public DelegationContext(String serviceSubject, String actingOnBehalfOfSubject) {
        this.serviceSubject = Objects.requireNonNull(serviceSubject);
        this.actingOnBehalfOfSubject = Objects.requireNonNull(actingOnBehalfOfSubject);
    }

    public void describeActingSubjectTo(Consumer<String> consumer) {
        consumer.accept(actingOnBehalfOfSubject);
    }

    public void describeServiceSubjectTo(Consumer<String> consumer) {
        consumer.accept(serviceSubject);
    }

    public boolean isActingFor(String subjectId) {
        return actingOnBehalfOfSubject.equals(subjectId);
    }

    @Override
    public boolean equals(Object o) {
        return this == o || (o instanceof DelegationContext other
                && serviceSubject.equals(other.serviceSubject)
                && actingOnBehalfOfSubject.equals(other.actingOnBehalfOfSubject));
    }

    @Override
    public int hashCode() {
        return Objects.hash(serviceSubject, actingOnBehalfOfSubject);
    }

    @Override
    public String toString() {
        return "DelegationContext[service=***, actingFor=***]";
    }
}
