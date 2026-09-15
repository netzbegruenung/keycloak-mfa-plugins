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
import org.keycloak.credential.CredentialProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;

import java.util.Locale;
import jakarta.ws.rs.core.MultivaluedMap;
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
			// TODO: get the alias from somewhere else or move config into realm or application scope
			AuthenticatorConfigModel config = context.getRealm().getAuthenticatorConfigByAlias("sms-2fa");
			if (config == null) {
				logger.error("No authenticator config with alias sms-2fa found, cannot send the phone validation SMS");
				context.failure();
				return;
			}

			String mobileNumber = authSession.getAuthNote("mobile_number");
			logger.infof("Validating phone number of user: %s", user.getUsername());

			SmsCode.Outcome outcome = new SmsCode(context.getSession(), config.getConfig()).issue(user, mobileNumber);
			LoginFormsProvider form = context.form()
				.setAttribute("realm", realm)
				.setAttribute("resendCooldown", outcome.cooldownSecondsRemaining());
			if (outcome.blocked()) {
				context.getEvent().clone().user(user).detail("reason", "sms_resend_limit").error(Errors.USER_TEMPORARILY_DISABLED);
				context.challenge(form
					.setError("smsAuthResendBlocked", String.valueOf(outcome.blockedMinutesRemaining()))
					.createForm(SmsAuthenticator.TPL_CODE));
				return;
			}
			if (outcome.coolingDown()) {
				context.challenge(form
					.setInfo("smsAuthResendCooldown", String.valueOf(outcome.cooldownSecondsRemaining()))
					.createForm(SmsAuthenticator.TPL_CODE));
				return;
			}

			Theme theme = context.getSession().theme().getTheme(Theme.Type.LOGIN);
			Locale locale = context.getSession().getContext().resolveLocale(user);
			String smsAuthText = theme.getEnhancedMessages(realm,locale).getProperty("smsAuthText");
			String smsText = String.format(smsAuthText, outcome.code(), outcome.remainingMinutes());

			SmsServiceFactory.get(config.getConfig()).send(mobileNumber, smsText);

			if (outcome.resent() && outcome.resendsLeft() == 0) {
				form.setSuccess("smsAuthCodeResentLast");
			} else if (outcome.resent()) {
				form.setSuccess("smsAuthCodeResent", String.valueOf(outcome.resendsLeft()));
			}
			context.challenge(form.createForm(SmsAuthenticator.TPL_CODE));
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			context.failure();
		}
	}

	@Override
	public void processAction(RequiredActionContext context) {
		MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
		if (formData.containsKey(SmsAuthenticator.RESEND_FIELD)) {
			requiredActionChallenge(context);
			return;
		}
		String enteredCode = formData.getFirst("code");

		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		String mobileNumber = authSession.getAuthNote("mobile_number");
		AuthenticatorConfigModel config = context.getRealm().getAuthenticatorConfigByAlias("sms-2fa");
		if (config == null) {
			logger.error("No authenticator config with alias sms-2fa found, cannot verify the phone validation SMS");
			context.failure();
			return;
		}

		SmsCode.Verification verification = new SmsCode(context.getSession(), config.getConfig()).verify(context.getUser(), enteredCode);
		if (verification == SmsCode.Verification.NO_CODE) {
			// Nothing to check against (e.g. the user was blocked and submitted anyway, or the
			// code was discarded): re-run the challenge, which sends a code or re-shows the block.
			requiredActionChallenge(context);
			return;
		}
		if (verification == SmsCode.Verification.VALID) {
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
		context.getEvent().clone().user(context.getUser()).error(Errors.INVALID_USER_CREDENTIALS);
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
