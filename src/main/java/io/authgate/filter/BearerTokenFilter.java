package io.authgate.filter;

import io.authgate.domain.model.ValidationOutcome;
import io.authgate.domain.model.ValidatedToken;
import io.authgate.validation.TokenValidator;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Jakarta Servlet filter that validates bearer tokens on incoming requests.
 *
 * <p>On success: sets {@link ValidatedToken} as request attribute.</p>
 * <p>On failure: returns 401 with WWW-Authenticate header and JSON error body.</p>
 */
public final class BearerTokenFilter implements Filter {

    public static final String DEFAULT_TOKEN_ATTRIBUTE = "io.authgate.validated.token";

    private final TokenValidator tokenValidator;
    private final Set<String> excludedPaths;
    private final String tokenAttribute;

    public BearerTokenFilter(TokenValidator tokenValidator, Set<String> excludedPaths, String tokenAttribute) {
        this.tokenValidator = Objects.requireNonNull(tokenValidator);
        this.excludedPaths = Objects.requireNonNullElse(excludedPaths, Set.of());
        this.tokenAttribute = Objects.requireNonNull(tokenAttribute);
    }

    public BearerTokenFilter(TokenValidator tokenValidator, Set<String> excludedPaths) {
        this(tokenValidator, excludedPaths, DEFAULT_TOKEN_ATTRIBUTE);
    }

    public BearerTokenFilter(TokenValidator tokenValidator) {
        this(tokenValidator, Set.of(), DEFAULT_TOKEN_ATTRIBUTE);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (!(request instanceof HttpServletRequest httpReq)
                || !(response instanceof HttpServletResponse httpResp)) {
            chain.doFilter(request, response);
            return;
        }

        if (isExcluded(httpReq.getRequestURI())) {
            chain.doFilter(request, response);
            return;
        }

        var authHeader = httpReq.getHeader("Authorization");
        if (authHeader == null || !authHeader.regionMatches(true, 0, "Bearer ", 0, 7)) {
            sendError(httpResp, "missing_token", "Authorization header with Bearer token is required.");
            return;
        }

        var outcome = tokenValidator.validateFromHeader(authHeader);

        switch (outcome) {
            case ValidationOutcome.Valid valid -> {
                httpReq.setAttribute(tokenAttribute, valid.token());
                chain.doFilter(request, response);
            }
            case ValidationOutcome.Rejected rejected -> {
                var code = new AtomicReference<>("invalid_token");
                var desc = new AtomicReference<>("Token validation failed");
                rejected.describeCodeTo(code::set);
                rejected.describeReasonTo(desc::set);
                sendError(httpResp, code.get(), desc.get());
            }
        }
    }

    private boolean isExcluded(String path) {
        return excludedPaths.stream().anyMatch(path::startsWith);
    }

    private void sendError(HttpServletResponse resp, String error, String description) throws IOException {
        resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        resp.setContentType("application/json");
        resp.setHeader("WWW-Authenticate", "Bearer error=\"" + error + "\"");
        resp.getWriter().write(
                "{\"error\":\"" + escapeJson(error)
                + "\",\"error_description\":\"" + escapeJson(description) + "\"}"
        );
    }

    private String escapeJson(String v) {
        return v.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
