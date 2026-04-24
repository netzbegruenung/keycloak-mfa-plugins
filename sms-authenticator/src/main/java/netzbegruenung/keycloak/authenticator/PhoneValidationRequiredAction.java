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

	private static final String ACTION_CHANGE_NUMBER = "change_number";

	@Override
	public void evaluateTriggers(RequiredActionContext context) {
	}

	@Override
	public void requiredActionChallenge(RequiredActionContext context) {

		try {
			UserModel user = context.getUser();
			RealmModel realm = context.getRealm();

			AuthenticationSessionModel authSession = context.getAuthenticationSession();
			// TODO: get the alias from somewhere else or move config into realm or application scope
			AuthenticatorConfigModel config = context.getRealm().getAuthenticatorConfigByAlias("sms-2fa");

			String mobileNumber = authSession.getAuthNote("mobile_number");
			logger.infof("Validating phone number: %s of user: %s", mobileNumber, user.getUsername());

			int length = Integer.parseInt(config.getConfig().get("length"));
			int ttl = Integer.parseInt(config.getConfig().get("ttl"));

			String code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
			authSession.setAuthNote("code", code);
			authSession.setAuthNote("ttl", Long.toString(System.currentTimeMillis() + (ttl * 1000L)));

			Theme theme = context.getSession().theme().getTheme(Theme.Type.LOGIN);
			Locale locale = context.getSession().getContext().resolveLocale(user);
			String smsAuthText = theme.getEnhancedMessages(realm,locale).getProperty("smsAuthText");
			String smsText = String.format(smsAuthText, code, Math.floorDiv(ttl, 60));

			SmsServiceFactory.get(config.getConfig()).send(mobileNumber, smsText);

			Response challenge = buildSmsCodeForm(context, realm, mobileNumber);
			context.challenge(challenge);
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			context.failure();
		}
	}

	@Override
	public void processAction(RequiredActionContext context) {
		String enrollment = context.getHttpRequest().getDecodedFormParameters().getFirst(SmsEnrollmentAbandon.FORM_PARAM);
		if (SmsEnrollmentAbandon.ACTION_CANCEL.equals(enrollment)) {
			SmsEnrollmentAbandon.abandonAndRedirect(context);
			return;
		}
		if (ACTION_CHANGE_NUMBER.equals(enrollment)) {
			handleChangeNumber(context);
			return;
		}

		String enteredCode = context.getHttpRequest().getDecodedFormParameters().getFirst("code");

		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		String mobileNumber = authSession.getAuthNote("mobile_number");
		String code = authSession.getAuthNote("code");
		String ttl = authSession.getAuthNote("ttl");

		if (code == null || ttl == null || enteredCode == null) {
			logger.warn("SMS code session state missing or no code entered");
			handleInvalidSmsCode(context, mobileNumber);
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
			handleInvalidSmsCode(context, mobileNumber);
		}
	}

	private void handleChangeNumber(RequiredActionContext context) {
		AuthenticationSessionModel session = context.getAuthenticationSession();
		UserModel user = context.getUser();
		clearSmsEnrollmentState(session);
		session.removeAuthNote("mobile_number");
		user.removeRequiredAction(PhoneValidationRequiredAction.PROVIDER_ID);
		user.removeRequiredAction(PhoneNumberRequiredAction.PROVIDER_ID);
		session.removeRequiredAction(PhoneValidationRequiredAction.PROVIDER_ID);
		session.removeRequiredAction(PhoneNumberRequiredAction.PROVIDER_ID);
		// Same as initial enrollment (enforcement): one User-level RA, not user+session duplicate, so
		// PhoneNumberRequiredAction.processAction + success() matches a first pass.
		user.addRequiredAction(PhoneNumberRequiredAction.PROVIDER_ID);
		session.addRequiredAction(PhoneNumberRequiredAction.PROVIDER_ID);
		// Do not reuse the current URL (old session_code) after changing execution: ClientSessionCode no longer
		// matches → "Page has expired". Same idea as RequiredActionContextResult#getActionUrl: new code from
		// generateCode(), server-shaped URL, execution = phone entry.
		new PhoneNumberRequiredAction().showPhoneNumberFormAfterChangeNumber(context);
	}

	private static void clearSmsEnrollmentState(AuthenticationSessionModel session) {
		session.removeAuthNote("code");
		session.removeAuthNote("ttl");
	}

	Response buildSmsCodeForm(RequiredActionContext context, RealmModel realm, String rawSendDestination) {
		String line = PhoneNumberRequiredAction.buildSmsDestinationHint(
			context.getSession(),
			realm,
			context.getUser(),
			rawSendDestination
		);
		return context.form()
			.setAttribute("realm", realm)
			.setAttribute("smsEnrollmentMode", Boolean.TRUE)
			.setAttribute("smsAuthSentToText", line)
			.createForm(SmsAuthenticator.TPL_CODE);
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

	private void handleInvalidSmsCode(RequiredActionContext context, String e164) {
		String line = PhoneNumberRequiredAction.buildSmsDestinationHint(
			context.getSession(),
			context.getRealm(),
			context.getUser(),
			e164
		);
		Response challenge = context
			.form()
			.setAttribute("realm", context.getRealm())
			.setAttribute("smsEnrollmentMode", Boolean.TRUE)
			.setAttribute("smsAuthSentToText", line)
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
