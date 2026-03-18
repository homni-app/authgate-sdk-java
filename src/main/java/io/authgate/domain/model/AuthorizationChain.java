package io.authgate.domain.model;

import io.authgate.domain.exception.AccessDeniedException;
import io.authgate.domain.exception.TokenValidationException;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Fluent authorization chain that combines token validation with permission checks.
 * Created via {@code AuthGate.authorize()} / {@code AuthGate.authorizeFromHeader()}.
 *
 * <p>Terminates with either {@link #evaluate()} (polymorphic result)
 * or {@link #orThrow()} (exception on failure).</p>
 */
public final class AuthorizationChain {

    private final ValidationOutcome outcome;
    private final Set<OAuthScope> requiredScopes = new LinkedHashSet<>();
    private String requiredAudience;
    private String requiredSubject;

    public AuthorizationChain(ValidationOutcome outcome) {
        this.outcome = outcome;
    }

    public AuthorizationChain scope(OAuthScope scope) {
        requiredScopes.add(scope);
        return this;
    }

    public AuthorizationChain audience(String audience) {
        this.requiredAudience = audience;
        return this;
    }

    public AuthorizationChain subject(String subject) {
        this.requiredSubject = subject;
        return this;
    }

    public AuthorizationResult evaluate() {
        return switch (outcome) {
            case ValidationOutcome.Rejected r -> new AuthorizationResult.Rejected(r.reason());
            case ValidationOutcome.Valid v -> checkPermissions(v.token());
        };
    }

    public ValidatedToken orThrow() {
        return switch (evaluate()) {
            case AuthorizationResult.Granted g -> g.token();
            case AuthorizationResult.Denied d -> throw new AccessDeniedException(d.reason().description());
            case AuthorizationResult.Rejected r -> throw new TokenValidationException(r.reason());
        };
    }

    private AuthorizationResult checkPermissions(ValidatedToken token) {
        for (OAuthScope scope : requiredScopes) {
            if (!token.hasScope(scope)) {
                return new AuthorizationResult.Denied(new DenialReason.MissingScope(scope));
            }
        }
        if (requiredAudience != null && !token.isIntendedFor(requiredAudience)) {
            return new AuthorizationResult.Denied(new DenialReason.AudienceMismatch(requiredAudience));
        }
        if (requiredSubject != null && !token.belongsTo(requiredSubject)) {
            return new AuthorizationResult.Denied(new DenialReason.SubjectMismatch(requiredSubject));
        }
        return new AuthorizationResult.Granted(token);
    }
}
