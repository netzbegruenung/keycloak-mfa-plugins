package netzbegruenung.keycloak.dev.resteasy;

import jakarta.ws.rs.core.*;
import jakarta.ws.rs.ext.MessageBodyReader;
import jakarta.ws.rs.ext.Providers;
import org.jboss.resteasy.core.ResteasyContext;
import org.jboss.resteasy.reactive.server.multipart.FormValue;
import org.jboss.resteasy.reactive.server.multipart.MultipartFormDataInput;
import org.keycloak.http.FormPartValue;
import org.keycloak.http.HttpRequest;
import org.keycloak.services.FormPartValueImpl;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Map;

import static jakarta.ws.rs.core.MediaType.MULTIPART_FORM_DATA_TYPE;

public class HttpRequestImpl implements HttpRequest {

	private final org.jboss.resteasy.spi.HttpRequest delegate;

	public <R> HttpRequestImpl(org.jboss.resteasy.spi.HttpRequest delegate) {
		this.delegate = delegate;
	}

	@Override
	public String getHttpMethod() {
		return delegate.getHttpMethod();
	}

	@Override
	public MultivaluedMap<String, String> getDecodedFormParameters() {
		return delegate.getDecodedFormParameters();
	}

	@Override
	public MultivaluedMap<String, FormPartValue> getMultiPartFormParameters() {
		try {
			MediaType mediaType = getHttpHeaders().getMediaType();

			if (!MULTIPART_FORM_DATA_TYPE.isCompatible(mediaType) || !mediaType.getParameters().containsKey("boundary")) {
				return new MultivaluedHashMap<>();
			}

			Providers providers = ResteasyContext.getContextData(Providers.class);
			MessageBodyReader<MultipartFormDataInput> multiPartProvider = providers.getMessageBodyReader(
				MultipartFormDataInput.class, null, null, MULTIPART_FORM_DATA_TYPE);
			MultipartFormDataInput inputs = multiPartProvider
				.readFrom(null, null, null, mediaType, getHttpHeaders().getRequestHeaders(),
					delegate.getInputStream());
			MultivaluedHashMap<String, FormPartValue> parts = new MultivaluedHashMap<>();

			for (Map.Entry<String, Collection<FormValue>> entry : inputs.getValues().entrySet()) {
				for (FormValue value : entry.getValue()) {
					if (!value.isFileItem()) {
						parts.add(entry.getKey(), new FormPartValueImpl(value.getValue()));
					} else {
						parts.add(entry.getKey(), new FormPartValueImpl(value.getFileItem().getInputStream()));
					}
				}
			}

			return parts;
		} catch (IOException cause) {
			throw new RuntimeException("Failed to parse multi part request", cause);
		}
	}

	@Override
	public HttpHeaders getHttpHeaders() {
		return delegate.getHttpHeaders();
	}

	@Override
	public X509Certificate[] getClientCertificateChain() {
		return (X509Certificate[]) delegate.getAttribute("jakarta.servlet.request.X509Certificate");
	}

	@Override
	public UriInfo getUri() {
		return delegate.getUri();
	}
}
