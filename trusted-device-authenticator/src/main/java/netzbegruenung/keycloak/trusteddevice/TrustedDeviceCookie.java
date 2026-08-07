package netzbegruenung.keycloak.trusteddevice;

import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.NewCookie;
import org.keycloak.models.KeycloakSession;

/**
 * Reads and writes the trusted-device cookie directly through the public HttpRequest/HttpResponse SPI.
 * The core CookieProvider/CookieType abstraction can't be used here since minting a new CookieType
 * constant requires a private builder method that's only callable from Keycloak core itself.
 */
public class TrustedDeviceCookie {

    public static final String NAME = "TRUSTED_DEVICE";

    private TrustedDeviceCookie() {
    }

    public static String read(KeycloakSession session) {
        Cookie cookie = session.getContext().getHttpRequest().getHttpHeaders().getCookies().get(NAME);
        return cookie == null ? null : cookie.getValue();
    }

    public static void write(KeycloakSession session, String encodedToken, int maxAgeSeconds) {
        // SameSite=None is only honoured by browsers together with Secure, which in turn requires HTTPS -
        // fall back to Lax without Secure on plain HTTP (e.g. a non-TLS-terminated dev/test server).
        boolean https = "https".equalsIgnoreCase(session.getContext().getUri().getBaseUri().getScheme());
        NewCookie.Builder builder = new NewCookie.Builder(NAME)
                .value(encodedToken)
                .path("/")
                .maxAge(maxAgeSeconds)
                .httpOnly(true);
        if (https) {
            builder.secure(true).sameSite(NewCookie.SameSite.NONE);
        } else {
            builder.sameSite(NewCookie.SameSite.LAX);
        }
        session.getContext().getHttpResponse().setCookieIfAbsent(builder.build());
    }
}
