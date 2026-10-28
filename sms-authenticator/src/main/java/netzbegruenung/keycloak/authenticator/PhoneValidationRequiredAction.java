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

import org.jboss.logging.Logger;
import org.keycloak.authentication.CredentialRegistrator;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import jakarta.ws.rs.core.MultivaluedMap;

public class PhoneValidationRequiredAction implements RequiredActionProvider, CredentialRegistrator {
	private static final Logger logger = Logger.getLogger(PhoneValidationRequiredAction.class);
	public static final String PROVIDER_ID = "phone_validation_config";

	@Override
	public void evaluateTriggers(RequiredActionContext context) {
	}

	@Override
	public void requiredActionChallenge(RequiredActionContext context) {
		sendCodeAndChallenge(context, false);
	}

	private void sendCodeAndChallenge(RequiredActionContext context, boolean resend) {
		context.getAuthenticationSession().addRequiredAction(PhoneNumberRequiredAction.PROVIDER_ID);
		try {
			UserModel user = context.getUser();
			RealmModel realm = context.getRealm();

			AuthenticationSessionModel authSession = context.getAuthenticationSession();
			// TODO: get the alias from somewhere else or move config into realm or application scope
			AuthenticatorConfigModel config = context.getRealm().getAuthenticatorConfigByAlias("sms-2fa");

			String mobileNumber = authSession.getAuthNote("mobile_number");
			logger.infof("Validating phone number: %s of user: %s", mobileNumber, user.getUsername());

			long wait = SmsAuthenticator.sendCode(context.getSession(), realm, user, authSession, config.getConfig(), mobileNumber, resend);

			LoginFormsProvider form = SmsAuthenticator.codeForm(context.form(), realm, authSession, config.getConfig(), mobileNumber);
			if (wait > 0) {
				form.setError("smsResendCooldown", wait);
			} else if (resend) {
				form.setSuccess("smsAuthCodeResent");
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
		if (formData.containsKey(SmsAuthenticator.RESEND)) {
			sendCodeAndChallenge(context, true);
			return;
		}
		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		String mobileNumber = authSession.getAuthNote("mobile_number");
		String error = SmsAuthenticator.verifyCode(authSession, formData.getFirst("code"));
		if (error != null) {
			AuthenticatorConfigModel config = context.getRealm().getAuthenticatorConfigByAlias("sms-2fa");
			context.challenge(SmsAuthenticator.codeForm(context.form(), context.getRealm(), authSession, config.getConfig(), mobileNumber)
				.setError(error)
				.createForm(SmsAuthenticator.TPL_CODE));
			return;
		}

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

	@Override
	public void close() {
	}

	@Override
	public String getCredentialType(KeycloakSession keycloakSession, AuthenticationSessionModel authenticationSessionModel) {
		return SmsAuthCredentialModel.TYPE;
	}
}
