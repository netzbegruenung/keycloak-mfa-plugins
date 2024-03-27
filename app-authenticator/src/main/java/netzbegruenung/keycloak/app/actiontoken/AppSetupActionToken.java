package netzbegruenung.keycloak.app.actiontoken;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.keycloak.authentication.actiontoken.DefaultActionToken;

public class AppSetupActionToken extends DefaultActionToken {

	public static final String TOKEN_TYPE = "app-setup-action-token";

	private static final String JSON_FIELD_ORIGINAL_AUTHENTICATION_SESSION_ID = "oasid";

	@JsonProperty(value = JSON_FIELD_ORIGINAL_AUTHENTICATION_SESSION_ID)
	private String originalAuthenticationSessionId;

	public AppSetupActionToken(String userId, Integer absoluteExpirationInSecs, String compoundAuthenticationSessionId, String clientId) {
		super(userId, TOKEN_TYPE, absoluteExpirationInSecs, null);
		this.issuer = clientId;
		this.originalAuthenticationSessionId = compoundAuthenticationSessionId;
	}

	private AppSetupActionToken() {
		// Required to deserialize from JWT
		super();
	}

	public String getOriginalAuthenticationSessionId() {
		return originalAuthenticationSessionId;
	}

	public void setOriginalAuthenticationSessionId(String originalCompoundAuthenticationSessionId) {
		this.originalAuthenticationSessionId = originalCompoundAuthenticationSessionId;
	}
}
