package netzbegruenung.keycloak.app.rest;

import jakarta.ws.rs.core.Response;

public class VerificationErrorResponseException extends Exception {
    private final Response response;

    public VerificationErrorResponseException(Response response) {
        this.response = response;
    }

    public Response getResponse() {
        return response;
    }
}
