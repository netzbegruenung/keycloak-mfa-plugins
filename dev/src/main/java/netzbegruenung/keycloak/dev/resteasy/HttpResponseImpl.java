package netzbegruenung.keycloak.dev.resteasy;

import jakarta.ws.rs.core.NewCookie;
import org.keycloak.http.HttpResponse;

import java.util.HashSet;
import java.util.Set;

public class HttpResponseImpl implements HttpResponse {

	private final org.jboss.resteasy.spi.HttpResponse delegate;
	private Set<NewCookie> newCookies;

	public HttpResponseImpl(org.jboss.resteasy.spi.HttpResponse delegate) {
		this.delegate = delegate;
	}

	@Override
	public int getStatus() {
		return delegate.getStatus();
	}

	@Override
	public void setStatus(int statusCode) {
		delegate.setStatus(statusCode);
	}

	@Override
	public void addHeader(String name, String value) {
		delegate.getOutputHeaders().add(name, value);
	}

	@Override
	public void setHeader(String name, String value) {
		delegate.getOutputHeaders().putSingle(name, value);
	}

	@Override
	public void setCookieIfAbsent(NewCookie newCookie) {
		if (newCookie == null) {
			throw new IllegalArgumentException("Cookie is null");
		}

		if (newCookies == null) {
			newCookies = new HashSet<>();
		}

		if (newCookies.add(newCookie)) {
			delegate.addNewCookie(newCookie);
		}
	}
}
