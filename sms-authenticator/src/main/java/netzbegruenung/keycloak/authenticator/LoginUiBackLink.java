package netzbegruenung.keycloak.authenticator;

import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.services.Urls;
import org.keycloak.sessions.AuthenticationSessionModel;

import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;

import java.net.URI;

/**
 * Resolves a sensible "back to app" target for SMS-related UIs instead of {@code href="/"} (Keycloak root).
 */
public final class LoginUiBackLink {

	/** Account Console path (Keycloak 25+): connection methods / MFA list. */
	private static final String ACCOUNT_SIGNING_IN_PATH = "account-security/signing-in";

	private LoginUiBackLink() {
	}

	/**
	 * After cancelling SMS enrollment from the account console, send users to Signing in rather than a generic restart.
	 */
	public static String smsEnrollmentAbortHref(RealmModel realm, AuthenticationSessionModel authSession, UriInfo uriInfo) {
		if (authSession != null && authSession.getClient() != null) {
			String cid = authSession.getClient().getClientId();
			if ("account-console".equals(cid) || "account".equals(cid)) {
				URI accountRoot = Urls.accountBase(uriInfo.getBaseUri()).build(realm.getName());
				return UriBuilder.fromUri(accountRoot).path(ACCOUNT_SIGNING_IN_PATH).build().normalize().toString();
			}
		}
		return href(realm, authSession, uriInfo);
	}

	public static String href(RealmModel realm, AuthenticationSessionModel authSession, UriInfo uriInfo) {
		URI baseUri = uriInfo.getBaseUri();
		ClientModel client = authSession != null ? authSession.getClient() : null;

		if (client != null) {
			String fromClient = firstNonBlank(client.getRootUrl(), client.getBaseUrl());
			String absolutized = absolutize(baseUri, fromClient);
			if (absolutized != null) {
				return absolutized;
			}
			String clientId = client.getClientId();
			if ("account-console".equals(clientId) || "account".equals(clientId)) {
				return Urls.accountBase(baseUri).build(realm.getName()).toString();
			}
		}

		if (authSession != null) {
			String redirect = authSession.getRedirectUri();
			if (redirect != null && !redirect.isBlank()) {
				return redirect.trim();
			}
		}

		return Urls.accountBase(baseUri).build(realm.getName()).toString();
	}

	private static String firstNonBlank(String a, String b) {
		if (a != null && !a.isBlank()) {
			return a;
		}
		if (b != null && !b.isBlank()) {
			return b;
		}
		return null;
	}

	private static String absolutize(URI keycloakBase, String ref) {
		if (ref == null || ref.isBlank()) {
			return null;
		}
		String t = ref.trim();
		try {
			URI u = URI.create(t);
			if (u.isAbsolute()) {
				return u.normalize().toString();
			}
			return keycloakBase.resolve(u).normalize().toString();
		} catch (IllegalArgumentException e) {
			return null;
		}
	}
}
