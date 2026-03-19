package io.authgate.http;

import io.authgate.application.port.HttpTransport;
import io.authgate.domain.exception.IdentityProviderException;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

/**
 * Decorator that wraps an {@link HttpTransport} with circuit breaker logic.
 *
 * <p>After {@code failureThreshold} consecutive failures the circuit opens and
 * immediately rejects calls with {@link IdentityProviderException} — no waiting
 * on IdP timeouts. The circuit stays open for {@code resetTimeout}, then allows
 * a single probe call (half-open). A successful call resets the counter.</p>
 *
 * <p>Thread-safe via {@link AtomicInteger} and {@link AtomicLong} — no locks,
 * no enum state machine.</p>
 */
public final class CircuitBreakerHttpTransport implements HttpTransport {

    private final HttpTransport delegate;
    private final int failureThreshold;
    private final long resetTimeoutMillis;

    private final AtomicInteger consecutiveFailures = new AtomicInteger(0);
    private final AtomicLong lastFailureTime = new AtomicLong(0);

    public CircuitBreakerHttpTransport(HttpTransport delegate,
                                       int failureThreshold,
                                       Duration resetTimeout) {
        this.delegate = delegate;
        this.failureThreshold = failureThreshold;
        this.resetTimeoutMillis = resetTimeout.toMillis();
    }

    @Override
    public TransportResponse postForm(String endpoint, Map<String, String> params) {
        rejectIfOpen();
        return execute(() -> delegate.postForm(endpoint, params));
    }

    @Override
    public TransportResponse fetchJson(String endpoint) {
        rejectIfOpen();
        return execute(() -> delegate.fetchJson(endpoint));
    }

    @Override
    public TransportResponse fetchJsonWithBearer(String endpoint, String bearerToken) {
        rejectIfOpen();
        return execute(() -> delegate.fetchJsonWithBearer(endpoint, bearerToken));
    }

    private void rejectIfOpen() {
        if (consecutiveFailures.get() >= failureThreshold) {
            long elapsed = System.currentTimeMillis() - lastFailureTime.get();
            if (elapsed < resetTimeoutMillis) {
                throw new IdentityProviderException(
                        "Circuit breaker open — identity provider unavailable "
                                + "(consecutive failures: " + consecutiveFailures.get() + ")");
            }
        }
    }

    private TransportResponse execute(Supplier<TransportResponse> call) {
        TransportResponse response;
        try {
            response = call.get();
        } catch (RuntimeException e) {
            recordFailure();
            throw e;
        }

        if (response.statusCode() >= 500) {
            recordFailure();
        } else {
            consecutiveFailures.set(0);
        }
        return response;
    }

    private void recordFailure() {
        consecutiveFailures.incrementAndGet();
        lastFailureTime.set(System.currentTimeMillis());
    }
}
