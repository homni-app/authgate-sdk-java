package io.authgate.application.port;

import java.util.Map;

/**
 * Outbound port for HTTP communication with Identity Provider.
 */
public interface HttpTransport {

    TransportResponse postForm(String endpoint, Map<String, String> params);

    TransportResponse fetchJson(String endpoint);

    record TransportResponse(int statusCode, Map<String, Object> body) {
        public boolean isSuccessful() {
            return statusCode >= 200 && statusCode < 300;
        }
    }
}
