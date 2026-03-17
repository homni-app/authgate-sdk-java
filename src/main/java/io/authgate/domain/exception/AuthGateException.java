package io.authgate.domain.exception;

public sealed class AuthGateException extends RuntimeException
        permits TokenValidationException, IdentityProviderException {

    protected AuthGateException(String message) { super(message); }
    protected AuthGateException(String message, Throwable cause) { super(message, cause); }
}
