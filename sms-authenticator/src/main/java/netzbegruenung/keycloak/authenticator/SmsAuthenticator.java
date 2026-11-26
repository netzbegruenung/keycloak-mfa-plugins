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
import netzbegruenung.keycloak.authenticator.verification.SmsVerification;
import netzbegruenung.keycloak.authenticator.verification.SmsVerificationContext;
import netzbegruenung.keycloak.authenticator.verification.SmsVerificationResult;

import org.jboss.logging.Logger;
import org.keycloak.authentication.CredentialValidator;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.util.JsonSerialization;

import jakarta.ws.rs.core.Response;
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

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		AuthenticatorConfigModel config = context.getAuthenticatorConfig();
		KeycloakSession session = context.getSession();
		UserModel user = context.getUser();
		RealmModel realm = context.getRealm();

		String mobileNumber = resolveMobileNumber(context);
		if (mobileNumber == null) {
			return;
		}

		try {
			SmsVerificationContext verificationContext = new SmsVerificationContext(
				session, realm, user, context.getAuthenticationSession(), config.getConfig(), mobileNumber);
			SmsVerification.getProvider(session, config.getConfig()).start(verificationContext);

			context.challenge(context.form()
				.setAttribute("realm", realm)
				.setAttribute("phoneNumber", mobileNumber)
				.createForm(TPL_CODE));
		} catch (Exception e) {
			logger.error("Failed to send SMS code", e);
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
				context.form().setError("smsAuthSmsNotSent", "Error. Use another method.")
					.createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
		}
	}

	@Override
	public void action(AuthenticationFlowContext context) {
		String enteredCode = context.getHttpRequest().getDecodedFormParameters().getFirst("code");

		String mobileNumber = resolveMobileNumber(context);
		Map<String, String> config = context.getAuthenticatorConfig().getConfig();

		SmsVerificationResult result;
		try {
			SmsVerificationContext verificationContext = new SmsVerificationContext(
				context.getSession(), context.getRealm(), context.getUser(), context.getAuthenticationSession(), config, mobileNumber);
			result = SmsVerification.getProvider(context.getSession(), config).verify(verificationContext, enteredCode);
		} catch (Exception e) {
			logger.error("Failed to verify SMS code", e);
			result = SmsVerificationResult.ERROR;
		}

		switch (result) {
			case VALID:
				context.success();
				break;
			case EXPIRED:
				context.getEvent().user(context.getUser()).error(EXPIRED_SMS_CODE);
				context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
					context.form().setError("smsAuthCodeExpired").createErrorPage(Response.Status.BAD_REQUEST));
				break;
			case INVALID:
				context.getEvent().user(context.getUser()).error(INVALID_SMS_CODE);
				Response challenge = context.form()
					.setAttribute("phoneNumber", mobileNumber)
					.setError("smsAuthCodeInvalid")
					.createForm(TPL_CODE);
				context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
				break;
			default:
				context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
					context.form().createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
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
}
