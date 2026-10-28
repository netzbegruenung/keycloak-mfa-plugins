/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @author Niko Köbler, https://www.n-k.de, @dasniko
 * @author Netzbegruenung e.V.
 * @author verdigado eG
 */

package netzbegruenung.keycloak.authenticator;

import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialData;
import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialModel;
import netzbegruenung.keycloak.authenticator.gateway.SmsServiceFactory;

import org.jboss.logging.Logger;
import org.keycloak.authentication.CredentialValidator;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;
import org.keycloak.util.JsonSerialization;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.util.Locale;
import java.util.Optional;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class SmsAuthenticator implements Authenticator, CredentialValidator<SmsAuthCredentialProvider> {

	private static final Logger logger = Logger.getLogger(SmsAuthenticator.class);
	static final String TPL_CODE = "login-sms.ftl";
	// Dedicated LOGIN_ERROR event errors, so SMS code failures are distinguishable from a wrong password
	// (invalid_user_credentials) and from Keycloak's own expired codes (expired_code)
	public static final String INVALID_SMS_CODE = "invalid_sms_code";
	public static final String EXPIRED_SMS_CODE = "expired_sms_code";
	static final String RESEND = "resend";
	static final String SENT_AT = "sent_at";

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		String mobileNumber = resolveMobileNumber(context);
		if (mobileNumber == null) {
			return;
		}
		sendCodeAndChallenge(context, mobileNumber, false);
	}

	private String resolveMobileNumber(AuthenticationFlowContext context) {
		AuthenticatorConfigModel config = context.getAuthenticatorConfig();
		UserModel user = context.getUser();

		Optional<CredentialModel> model = user.credentialManager().getStoredCredentialsByTypeStream(SmsAuthCredentialModel.TYPE).findFirst();
		String mobileNumber;
		try {
			mobileNumber = JsonSerialization.readValue(model.orElseThrow().getCredentialData(), SmsAuthCredentialData.class).getMobileNumber();
		} catch (IOException e1) {
			logger.warn(e1.getMessage(), e1);
			return null;
		}

		// When storeInAttribute is active, the attribute is the source of truth
		// Allows admins to update the number without requiring the user to re-enroll.
		boolean storeInAttribute = Boolean.parseBoolean(config.getConfig().getOrDefault("storeInAttribute", "false"));
		if (storeInAttribute) {
			String mobileNumberAttribute = config.getConfig().getOrDefault("mobileNumberAttribute", "mobile_number");
			String attributeNumber = user.getAttributeStream(mobileNumberAttribute)
				.filter(n -> n != null && !n.isBlank())
				.findFirst()
				.orElse(null);
			if (attributeNumber != null) {
				mobileNumber = attributeNumber;
			} else {
				logger.warnf("storeInAttribute is active but attribute '%s' is empty for user %s, falling back to credential value",
					mobileNumberAttribute, user.getUsername());
			}
		}
		return mobileNumber;
	}

	private void sendCodeAndChallenge(AuthenticationFlowContext context, String mobileNumber, boolean resend) {
		try {
			long wait = sendCode(context.getSession(), context.getRealm(), context.getUser(),
				context.getAuthenticationSession(), context.getAuthenticatorConfig().getConfig(), mobileNumber, resend);
			LoginFormsProvider form = context.form()
				.setAttribute("realm", context.getRealm())
				.setAttribute("phoneNumber", mobileNumber);
			if (wait > 0) {
				form.setError("smsResendCooldown", wait);
			}
			context.challenge(form.createForm(TPL_CODE));
		} catch (Exception e) {
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
				context.form().setError("smsAuthSmsNotSent", "Error. Use another method.")
					.createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
		}
	}

	/**
	 * Sends a new code. Only resends are throttled: entering the step always sends, because the
	 * email authenticator shares the "code" note, so the stored code may not be ours.
	 * Returns 0 if sent, otherwise the seconds left until a resend is allowed.
	 */
	static long sendCode(KeycloakSession session, RealmModel realm, UserModel user, AuthenticationSessionModel authSession,
						 Map<String, String> config, String mobileNumber, boolean resend) throws IOException {
		String sentAt = authSession.getAuthNote(SENT_AT);
		if (resend && sentAt != null) {
			String cooldown = config.get("resendCooldown");
			long cooldownMillis = (cooldown == null || cooldown.isBlank() ? 60 : Long.parseLong(cooldown.trim())) * 1000L;
			long waitMillis = Long.parseLong(sentAt) + cooldownMillis - System.currentTimeMillis();
			if (waitMillis > 0) {
				return (waitMillis + 999) / 1000;
			}
		}

		int length = Integer.parseInt(config.get("length"));
		int ttl = Integer.parseInt(config.get("ttl"));
		String code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);

		Theme theme = session.theme().getTheme(Theme.Type.LOGIN);
		Locale locale = session.getContext().resolveLocale(user);
		String smsAuthText = theme.getEnhancedMessages(realm,locale).getProperty("smsAuthText");
		String smsText = String.format(smsAuthText, code, Math.floorDiv(ttl, 60));

		SmsServiceFactory.get(config).send(mobileNumber, smsText);

		authSession.setAuthNote("code", code);
		authSession.setAuthNote("ttl", Long.toString(System.currentTimeMillis() + (ttl * 1000L)));
		authSession.setAuthNote(SENT_AT, Long.toString(System.currentTimeMillis()));
		return 0;
	}

	@Override
	public void action(AuthenticationFlowContext context) {
		MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
		// Resend shares the code form, so it must not count as a failed attempt.
		if (formData.containsKey(RESEND)) {
			String mobileNumber = resolveMobileNumber(context);
			if (mobileNumber != null) {
				sendCodeAndChallenge(context, mobileNumber, true);
			}
			return;
		}
		String enteredCode = formData.getFirst("code");

		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		String code = authSession.getAuthNote("code");
		String ttl = authSession.getAuthNote("ttl");

		if (code == null || ttl == null) {
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
				context.form().createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
			return;
		}

		boolean isValid = enteredCode.equals(code);
		if (isValid) {
			if (Long.parseLong(ttl) < System.currentTimeMillis()) {
				// expired
				context.getEvent().user(context.getUser()).error(EXPIRED_SMS_CODE);
				context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
					context.form().setError("smsAuthCodeExpired").createErrorPage(Response.Status.BAD_REQUEST));
			} else {
				// valid
				context.success();
			}
		} else {
			// invalid
			String mobileNumber = resolveMobileNumber(context);
			context.getEvent().user(context.getUser()).error(INVALID_SMS_CODE);
			Response challenge = context.form()
				.setAttribute("phoneNumber", mobileNumber)
				.setError("smsAuthCodeInvalid")
				.createForm("login-sms.ftl");
			context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
		}
	}

	@Override
	public boolean requiresUser() {
		return true;
	}

	@Override
	public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
		return getCredentialProvider(session).isConfiguredFor(realm, user, getType(session));
	}

	@Override
	public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
		user.addRequiredAction(PhoneNumberRequiredAction.PROVIDER_ID);
	}

	public List<RequiredActionFactory> getRequiredActions(KeycloakSession session) {
		return Collections.singletonList((PhoneNumberRequiredActionFactory)session.getKeycloakSessionFactory().getProviderFactory(RequiredActionProvider.class, PhoneNumberRequiredAction.PROVIDER_ID));
	}

	@Override
	public void close() {
	}

	@Override
	public SmsAuthCredentialProvider getCredentialProvider(KeycloakSession session) {
		return (SmsAuthCredentialProvider)session.getProvider(CredentialProvider.class, SmsAuthCredentialProviderFactory.PROVIDER_ID);
	}
}
