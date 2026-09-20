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
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.theme.Theme;
import org.keycloak.util.JsonSerialization;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.util.Locale;
import java.util.Optional;
import java.io.IOException;
import java.util.Collections;
import java.util.List;

public class SmsAuthenticator implements Authenticator, CredentialValidator<SmsAuthCredentialProvider> {

	private static final Logger logger = Logger.getLogger(SmsAuthenticator.class);
	static final String TPL_CODE = "login-sms.ftl";
	/** Name of the "Resend code" submit button in {@link #TPL_CODE}. */
	static final String RESEND_FIELD = "resend";

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		AuthenticatorConfigModel config = context.getAuthenticatorConfig();
		KeycloakSession session = context.getSession();
		UserModel user = context.getUser();
		RealmModel realm = context.getRealm();

		Optional<CredentialModel> model = context.getUser().credentialManager().getStoredCredentialsByTypeStream(SmsAuthCredentialModel.TYPE).findFirst();
		String mobileNumber;
		try {
			mobileNumber = JsonSerialization.readValue(model.orElseThrow().getCredentialData(), SmsAuthCredentialData.class).getMobileNumber();
		} catch (IOException e1) {
			logger.warn(e1.getMessage(), e1);
			return;
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

		SmsCode.Outcome outcome = new SmsCode(session, config.getConfig()).issue(user, mobileNumber);
		LoginFormsProvider form = context.form()
			.setAttribute("realm", realm)
			.setAttribute("phoneNumber", mobileNumber)
			.setAttribute("resendCooldown", outcome.cooldownSecondsRemaining());
		if (outcome.blocked()) {
			context.getEvent().clone().user(user).detail("reason", "sms_resend_limit").error(Errors.USER_TEMPORARILY_DISABLED);
			context.challenge(form
				.setError("smsAuthResendBlocked", String.valueOf(outcome.blockedMinutesRemaining()))
				.createForm(TPL_CODE));
			return;
		}
		if (outcome.coolingDown()) {
			context.challenge(form
				.setInfo("smsAuthResendCooldown", String.valueOf(outcome.cooldownSecondsRemaining()))
				.createForm(TPL_CODE));
			return;
		}

		try {
			Theme theme = session.theme().getTheme(Theme.Type.LOGIN);
			Locale locale = session.getContext().resolveLocale(user);
			String smsAuthText = theme.getEnhancedMessages(realm,locale).getProperty("smsAuthText");
			String smsText = String.format(smsAuthText, outcome.code(), outcome.remainingMinutes());

			SmsServiceFactory.get(config.getConfig()).send(mobileNumber, smsText);

			if (outcome.resent() && outcome.resendsLeft() == 0) {
				form.setSuccess("smsAuthCodeResentLast");
			} else if (outcome.resent()) {
				form.setSuccess("smsAuthCodeResent", String.valueOf(outcome.resendsLeft()));
			}
			context.challenge(form.createForm(TPL_CODE));
		} catch (Exception e) {
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
				context.form().setError("smsAuthSmsNotSent", "Error. Use another method.")
					.createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
		}
	}

	@Override
	public void action(AuthenticationFlowContext context) {
		MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
		if (formData.containsKey(RESEND_FIELD)) {
			// "Resend code" button: re-run the challenge, which re-sends the current code or
			// issues a new one, subject to the re-send limit.
			authenticate(context);
			return;
		}
		// May be null: a GET on the action URL with session_code reaches action() without form data.
		String enteredCode = formData.getFirst("code");

		SmsCode smsCode = new SmsCode(context.getSession(), context.getAuthenticatorConfig().getConfig());
		switch (smsCode.verify(context.getUser(), enteredCode)) {
			case NO_CODE -> {
				// Nothing to check against (e.g. the user was blocked on a fresh login and
				// submitted anyway, or the code was discarded): re-run the challenge, which
				// sends a code or re-shows the block.
				authenticate(context);
			}
			case EXPIRED -> context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
				context.form().setError("smsAuthCodeExpired").createErrorPage(Response.Status.BAD_REQUEST));
			case VALID -> context.success();
			case INVALID -> {
				String mobileNumber = getMobileNumber(context);
				context.getEvent().user(context.getUser()).error("invalid_user_credentials");
				Response challenge = context.form()
					.setAttribute("phoneNumber", mobileNumber)
					.setError("smsAuthCodeInvalid")
					.createForm("login-sms.ftl");
				context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
			}
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

	private String getMobileNumber(AuthenticationFlowContext context) {
		Optional<CredentialModel> model = context.getUser().credentialManager()
			.getStoredCredentialsByTypeStream(SmsAuthCredentialModel.TYPE).findFirst();
		try {
			return JsonSerialization.readValue(model.orElseThrow().getCredentialData(), SmsAuthCredentialData.class).getMobileNumber();
		} catch (IOException e) {
			logger.warn(e.getMessage(), e);
			return null;
		}
	}
}
