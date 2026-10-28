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
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
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
	// Prefixed because the email authenticator uses plain "code" and "ttl" in the same auth session.
	static final String CODE = "sms_code";
	static final String TTL = "sms_ttl";
	static final String SENT_AT = "sms_sent_at";
	static final String ATTEMPTS = "sms_attempts";
	// Caps guessing even when the realm has brute force detection turned off (the default).
	private static final int MAX_ATTEMPTS = 5;

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
			Map<String, String> config = context.getAuthenticatorConfig().getConfig();
			AuthenticationSessionModel authSession = context.getAuthenticationSession();
			long wait = sendCode(context.getSession(), context.getRealm(), context.getUser(), authSession, config, mobileNumber, resend);
			LoginFormsProvider form = codeForm(context.form(), context.getRealm(), authSession, config, mobileNumber);
			if (wait > 0) {
				form.setError("smsResendCooldown", wait);
			} else if (resend) {
				form.setSuccess("smsAuthCodeResent");
			}
			context.challenge(form.createForm(TPL_CODE));
		} catch (Exception e) {
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
				context.form().setError("smsAuthSmsNotSent", "Error. Use another method.")
					.createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
		}
	}

	/**
	 * Sends the code by SMS, at most once per resend cooldown, so neither the resend button nor
	 * reloading the page can be used to send SMS in bulk.
	 * Returns the seconds the user must wait for a new SMS when they need to be told, otherwise 0.
	 */
	static long sendCode(KeycloakSession session, RealmModel realm, UserModel user, AuthenticationSessionModel authSession,
						 Map<String, String> config, String mobileNumber, boolean resend) throws IOException {
		String code = authSession.getAuthNote(CODE);
		long wait = resendIn(authSession, config);
		if (wait > 0) {
			// A reload or a return to this step keeps the code already sent.
			return resend || code == null ? wait : 0;
		}

		int ttl = Integer.parseInt(config.get("ttl"));
		// Sending the same code again means a first SMS that arrives late still works.
		if (code == null || isExpired(authSession)) {
			code = SecretGenerator.getInstance().randomString(Integer.parseInt(config.get("length")), SecretGenerator.DIGITS);
			authSession.removeAuthNote(ATTEMPTS);
		}

		Theme theme = session.theme().getTheme(Theme.Type.LOGIN);
		Locale locale = session.getContext().resolveLocale(user);
		String smsAuthText = theme.getEnhancedMessages(realm,locale).getProperty("smsAuthText");
		String smsText = String.format(smsAuthText, code, Math.floorDiv(ttl, 60));

		SmsServiceFactory.get(config).send(mobileNumber, smsText);

		authSession.setAuthNote(CODE, code);
		authSession.setAuthNote(TTL, Long.toString(System.currentTimeMillis() + (ttl * 1000L)));
		authSession.setAuthNote(SENT_AT, Long.toString(System.currentTimeMillis()));
		return 0;
	}

	/** Seconds until another SMS may be sent. */
	static long resendIn(AuthenticationSessionModel authSession, Map<String, String> config) {
		String sentAt = authSession.getAuthNote(SENT_AT);
		if (sentAt == null) {
			return 0;
		}
		String cooldown = config.get("resendCooldown");
		long cooldownMillis = (cooldown == null || cooldown.isBlank() ? 60 : Long.parseLong(cooldown.trim())) * 1000L;
		long waitMillis = Long.parseLong(sentAt) + cooldownMillis - System.currentTimeMillis();
		return waitMillis > 0 ? (waitMillis + 999) / 1000 : 0;
	}

	/** Returns null if the entered code is right, otherwise the error message key. */
	static String verifyCode(AuthenticationSessionModel authSession, String enteredCode) {
		String code = authSession.getAuthNote(CODE);
		if (code == null || isExpired(authSession)) {
			clearCode(authSession);
			return "smsAuthCodeExpired";
		}
		if (enteredCode != null && MessageDigest.isEqual(code.getBytes(StandardCharsets.UTF_8),
			enteredCode.trim().getBytes(StandardCharsets.UTF_8))) {
			clearCode(authSession);
			return null;
		}
		String attemptsNote = authSession.getAuthNote(ATTEMPTS);
		int attempts = (attemptsNote == null ? 0 : Integer.parseInt(attemptsNote)) + 1;
		if (attempts >= MAX_ATTEMPTS) {
			clearCode(authSession);
			return "smsAuthCodeTooManyAttempts";
		}
		authSession.setAuthNote(ATTEMPTS, Integer.toString(attempts));
		return "smsAuthCodeInvalid";
	}

	/** Invalidates the current code. Keeps the send time, so the cooldown still holds. */
	static void clearCode(AuthenticationSessionModel authSession) {
		authSession.removeAuthNote(CODE);
		authSession.removeAuthNote(TTL);
		authSession.removeAuthNote(ATTEMPTS);
	}

	private static boolean isExpired(AuthenticationSessionModel authSession) {
		String ttl = authSession.getAuthNote(TTL);
		return ttl == null || Long.parseLong(ttl) < System.currentTimeMillis();
	}

	static LoginFormsProvider codeForm(LoginFormsProvider form, RealmModel realm, AuthenticationSessionModel authSession,
									   Map<String, String> config, String mobileNumber) {
		return form
			.setAttribute("realm", realm)
			.setAttribute("phoneNumber", mobileNumber)
			.setAttribute("resendIn", resendIn(authSession, config));
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
		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		String error = verifyCode(authSession, formData.getFirst("code"));
		if (error == null) {
			context.success();
			return;
		}

		boolean expired = "smsAuthCodeExpired".equals(error);
		context.getEvent().user(context.getUser()).error(expired ? EXPIRED_SMS_CODE : INVALID_SMS_CODE);
		// Back to the form rather than an error page, so the user can resend instead of starting over.
		Response challenge = codeForm(context.form(), context.getRealm(), authSession,
			context.getAuthenticatorConfig().getConfig(), resolveMobileNumber(context))
			.setError(error)
			.createForm(TPL_CODE);
		context.failureChallenge(expired ? AuthenticationFlowError.EXPIRED_CODE : AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
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
