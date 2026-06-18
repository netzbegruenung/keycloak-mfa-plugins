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
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;

import java.util.Locale;
import java.util.Map;
import jakarta.ws.rs.core.Response;

public class PhoneValidationRequiredAction implements RequiredActionProvider, CredentialRegistrator {
	private static final Logger logger = Logger.getLogger(PhoneValidationRequiredAction.class);
	public static final String PROVIDER_ID = "phone_validation_config";

	@Override
	public void evaluateTriggers(RequiredActionContext context) {
	}

	@Override
	public void requiredActionChallenge(RequiredActionContext context) {
		context.getAuthenticationSession().addRequiredAction(PhoneNumberRequiredAction.PROVIDER_ID);
		try {
			UserModel user = context.getUser();
			RealmModel realm = context.getRealm();

			AuthenticationSessionModel authSession = context.getAuthenticationSession();
			Map<String, String> config = SmsRegistrationConfigResolver.getMergedRegistrationConfig(realm);
			if (config.isEmpty()) {
				logger.errorf(
					"Phone validation failed, no SMS registration configuration (legacy alias %s). "
						+ "Use required action \"Update Mobile Number\" (gear) for inline SMS settings, or create an authenticator config with that alias on your SMS flow step.",
					SmsRegistrationConfigResolver.LEGACY_DEFAULT_ALIAS
				);
				context.failure();
				return;
			}

			String mobileNumber = authSession.getAuthNote("mobile_number");
			logger.infof("Validating phone number: %s of user: %s", mobileNumber, user.getUsername());

			String lenStr = config.getOrDefault("length", SmsRegistrationConfigResolver.DEFAULT_LENGTH).trim();
			String ttlStr = config.getOrDefault("ttl", SmsRegistrationConfigResolver.DEFAULT_TTL_SECONDS).trim();
			int length;
			int ttl;
			try {
				length = Integer.parseInt(lenStr);
				ttl = Integer.parseInt(ttlStr);
			} catch (NumberFormatException e) {
				logger.errorf("Invalid SMS registration length or ttl (length=%s ttl=%s)", lenStr, ttlStr, e);
				context.failure();
				return;
			}

			String code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
			authSession.setAuthNote("code", code);
			authSession.setAuthNote("ttl", Long.toString(System.currentTimeMillis() + (ttl * 1000L)));

			Theme theme = context.getSession().theme().getTheme(Theme.Type.LOGIN);
			Locale locale = context.getSession().getContext().resolveLocale(user);
			String smsAuthText = theme.getEnhancedMessages(realm,locale).getProperty("smsAuthText");
			String smsText = String.format(smsAuthText, code, Math.floorDiv(ttl, 60));

			SmsRegistrationConfigResolver.logWarningIfUsingLegacySmsAuthenticatorConfig(realm);
			SmsServiceFactory.get(config).send(mobileNumber, smsText);

			Response challenge = context.form()
				.setAttribute("realm", realm)
				.createForm(SmsAuthenticator.TPL_CODE);
			context.challenge(challenge);
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			context.failure();
		}
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
			context.getAuthenticationSession().removeRequiredAction(PhoneNumberRequiredAction.PROVIDER_ID);
			handlePhoneToAttribute(context, mobileNumber);
			context.success();
		} else {
			// invalid or expired
			handleInvalidSmsCode(context);
		}
	}

	private void handlePhoneToAttribute(RequiredActionContext context, String mobileNumber) {
		Map<String, String> config = SmsRegistrationConfigResolver.getMergedRegistrationConfig(context.getRealm());
		if (config.isEmpty()) {
			logger.warn("No SMS registration configuration, skip phone number to attribute check");
		} else if (Boolean.parseBoolean(config.getOrDefault("storeInAttribute", "false"))) {
			context.getUser().setSingleAttribute("mobile_number", mobileNumber);
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
