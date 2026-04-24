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

import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialModel;
import netzbegruenung.keycloak.authenticator.gateway.SmsServiceFactory;

import org.jboss.logging.Logger;
import org.keycloak.authentication.CredentialRegistrator;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;

import java.util.Locale;
import jakarta.ws.rs.core.Response;

public class PhoneValidationRequiredAction implements RequiredActionProvider, CredentialRegistrator {
	private static final Logger logger = Logger.getLogger(PhoneValidationRequiredAction.class);
	public static final String PROVIDER_ID = "phone_validation_config";
	private static final String LAST_OTP_SENT = "last_otp_sent";
	private static final long DEBOUNCE_SECONDS = 30; // Minimum time between SMS sends (in seconds)

	@Override
	public void evaluateTriggers(RequiredActionContext context) {
	}

	@Override
	public void requiredActionChallenge(RequiredActionContext context) {
		context.getUser().addRequiredAction(PhoneNumberRequiredAction.PROVIDER_ID);
		try {
			UserModel user = context.getUser();
			RealmModel realm = context.getRealm();

			AuthenticationSessionModel authSession = context.getAuthenticationSession();
			// TODO: get the alias from somewhere else or move config into realm or application scope
			AuthenticatorConfigModel config = context.getRealm().getAuthenticatorConfigByAlias("sms-2fa");

			String mobileNumber = authSession.getAuthNote("mobile_number");
			logger.infof("Validating phone number: %s of user: %s", mobileNumber, user.getUsername());

			// Check if an SMS can be sent (debouncing logic)
			if (canSendOtp(authSession)) {
				sendSmsAndCreateForm(context, authSession, config, mobileNumber);
				logger.info("Initial SMS OTP sent for user " + user.getUsername());
			} else {
				// If debouncing prevents sending, show form with a message indicating remaining
				// time
				long secondsRemaining = getSecondsRemaining(authSession);
				Response challenge = context.form()
						.setAttribute("realm", realm)
						.setError("smsDebounceMessage", String.valueOf(secondsRemaining))
						.createForm(SmsAuthenticator.TPL_CODE);
				context.challenge(challenge);
				logger.infof("SMS resend rejected for user %s (%d seconds remaining)", user.getUsername(),
						secondsRemaining);
			}
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			context.failure();
		}
	}

	private boolean canSendOtp(AuthenticationSessionModel authSession) {
		String lastSent = authSession.getAuthNote(LAST_OTP_SENT);
		long currentTime = Time.currentTime();
		long lastTime = lastSent != null ? Long.parseLong(lastSent) : 0;
		return currentTime - lastTime >= DEBOUNCE_SECONDS;
	}

	private long getSecondsRemaining(AuthenticationSessionModel authSession) {
		String lastSent = authSession.getAuthNote(LAST_OTP_SENT);
		long lastTime = lastSent != null ? Long.parseLong(lastSent) : 0;
		return lastTime > 0 ? DEBOUNCE_SECONDS - (Time.currentTime() - lastTime) : 0;
	}

	private void sendSmsAndCreateForm(RequiredActionContext context, AuthenticationSessionModel authSession,
			AuthenticatorConfigModel config, String mobileNumber) throws Exception {
		int length = Integer.parseInt(config.getConfig().get("length"));
		int ttl = Integer.parseInt(config.getConfig().get("ttl"));

		String code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
		authSession.setAuthNote("code", code);
		authSession.setAuthNote("ttl", Long.toString(System.currentTimeMillis() + (ttl * 1000L)));
		authSession.setAuthNote(LAST_OTP_SENT, String.valueOf(Time.currentTime()));

		Theme theme = context.getSession().theme().getTheme(Theme.Type.LOGIN);
		Locale locale = context.getSession().getContext().resolveLocale(context.getUser());
		String smsAuthText = theme.getEnhancedMessages(context.getRealm(), locale).getProperty("smsAuthText");
		String smsText = String.format(smsAuthText, code, Math.floorDiv(ttl, 60));

		if (authSession.getAuthNote("numberFormatNumberInUse") == null) {
			// smsText = authSession.getAuthNote("numberFormatNumberInUse") + ": " +
			// smsText;
			SmsServiceFactory.get(config.getConfig()).send(mobileNumber, smsText);
		} else {
			logger.warnf("The phone number %s is already in use.", mobileNumber);

		}

		context.getUser().removeRequiredAction(PhoneValidationRequiredAction.PROVIDER_ID);

		Response challenge = context.form()
				.setAttribute("realm", context.getRealm())
				.createForm(SmsAuthenticator.TPL_CODE);
		context.challenge(challenge);
	}

	@Override
	public void processAction(RequiredActionContext context) {
		String enteredCode = context.getHttpRequest().getDecodedFormParameters().getFirst("code");

		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		String mobileNumber = authSession.getAuthNote("mobile_number");
		String code = authSession.getAuthNote("code");
		String ttl = authSession.getAuthNote("ttl");

		if (code == null || ttl == null || enteredCode == null) {
			logger.warn("Phone number is not set");
			handleInvalidSmsCode(context);
			return;
		}

		boolean isValid = enteredCode.equals(code);
		if (isValid && Long.parseLong(ttl) > System.currentTimeMillis()) {
			// valid
			SmsAuthCredentialProvider smnp = (SmsAuthCredentialProvider) context.getSession().getProvider(CredentialProvider.class, "mobile-number");
			if (!smnp.isConfiguredFor(context.getRealm(), context.getUser(), SmsAuthCredentialModel.TYPE)) {
				smnp.createCredential(context.getRealm(), context.getUser(), SmsAuthCredentialModel.createSmsAuthenticator(mobileNumber));
			} else {
				smnp.updateCredential(
					context.getRealm(),
					context.getUser(),
					new UserCredentialModel("random_id", "mobile-number", mobileNumber)
				);
			}
			context.getUser().removeRequiredAction(PhoneNumberRequiredAction.PROVIDER_ID);
			handlePhoneToAttribute(context, mobileNumber);
			context.success();
		} else {
			// invalid or expired
			handleInvalidSmsCode(context);
		}
	}

	private void handlePhoneToAttribute(RequiredActionContext context, String mobileNumber) {
		AuthenticatorConfigModel config = context.getRealm().getAuthenticatorConfigByAlias("sms-2fa");
		if (config == null) {
			logger.warn("No config alias sms-2fa found, skip phone number to attribute check");
		} else {
			if (Boolean.parseBoolean(config.getConfig().get("storeInAttribute"))) {
				context.getUser().setSingleAttribute("mobile_number", mobileNumber);
			}
		}
	}

	private void handleInvalidSmsCode(RequiredActionContext context) {
		Response challenge = context
			.form()
			.setAttribute("realm", context.getRealm())
			.setError("smsAuthCodeInvalid")
			.createForm(SmsAuthenticator.TPL_CODE);
		context.challenge(challenge);
	}

	@Override
	public void close() {
	}

	@Override
	public String getCredentialType(KeycloakSession keycloakSession, AuthenticationSessionModel authenticationSessionModel) {
		return SmsAuthCredentialModel.TYPE;
	}
}
