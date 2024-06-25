package netzbegruenung.keycloak.dev.resteasy;

import org.jboss.resteasy.core.ResteasyContext;
import org.keycloak.http.HttpRequest;
import org.keycloak.http.HttpResponse;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.DefaultKeycloakContext;

public class ResteasyKeycloakContext extends DefaultKeycloakContext {
	public ResteasyKeycloakContext(KeycloakSession session) {
		super(session);
	}

	@Override
	protected HttpRequest createHttpRequest() {
		return new HttpRequestImpl(ResteasyContext.getContextData(org.jboss.resteasy.spi.HttpRequest.class));
	}

	@Override
	protected HttpResponse createHttpResponse() {
		return new HttpResponseImpl(ResteasyContext.getContextData(org.jboss.resteasy.spi.HttpResponse.class));
	}
}
