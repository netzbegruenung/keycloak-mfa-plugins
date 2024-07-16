package netzbegruenung.keycloak.app.rest;

import jakarta.ws.rs.container.AsyncResponse;

import java.util.concurrent.ScheduledFuture;

public record DeviceConnection(AsyncResponse asyncResponse, ScheduledFuture<?> evictionJob) {
}
