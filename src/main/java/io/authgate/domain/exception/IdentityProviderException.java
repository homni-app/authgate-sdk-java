package io.authgate.domain.exception;

public final class IdentityProviderException extends AuthGateException {
    public IdentityProviderException(String message) { super(message); }
    public IdentityProviderException(String message, Throwable cause) { super(message, cause); }
}
