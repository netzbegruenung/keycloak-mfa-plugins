package netzbegruenung.keycloak.authenticator;

import org.jboss.logging.Logger;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import jakarta.ws.rs.core.Response;

import java.net.URI;

/**
 * Shared cancel path for SMS enrollment (phone or code step); same redirect for all related required actions.
 */
public final class SmsEnrollmentAbandon {

	public static final String FORM_PARAM = "sms_enrollment_action";
	public static final String ACTION_CANCEL = "cancel";

	private static final Logger logger = Logger.getLogger(SmsEnrollmentAbandon.class);

	private SmsEnrollmentAbandon() {
	}

	public static void abandonAndRedirect(RequiredActionContext context) {
		AuthenticationSessionModel session = context.getAuthenticationSession();
		UserModel user = context.getUser();
		session.removeAuthNote("code");
		session.removeAuthNote("ttl");
		session.removeAuthNote("mobile_number");
		user.removeRequiredAction(PhoneNumberRequiredAction.PROVIDER_ID);
		user.removeRequiredAction(PhoneValidationRequiredAction.PROVIDER_ID);
		session.removeRequiredAction(PhoneNumberRequiredAction.PROVIDER_ID);
		session.removeRequiredAction(PhoneValidationRequiredAction.PROVIDER_ID);
		logger.infof("SMS enrollment abandoned: %s", user.getUsername());
		URI target = URI.create(LoginUiBackLink.smsEnrollmentAbortHref(context.getRealm(), session, context.getUriInfo()));
		context.challenge(Response.seeOther(target).build());
	}
}
