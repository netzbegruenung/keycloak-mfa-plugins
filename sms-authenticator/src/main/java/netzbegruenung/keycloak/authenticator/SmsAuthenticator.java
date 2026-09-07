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
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;
import org.keycloak.util.JsonSerialization;

import jakarta.ws.rs.core.Response;
import java.util.Locale;
import java.util.Optional;
import java.io.IOException;
import java.util.Collections;
import java.util.List;

// Deliberately NOT a CredentialValidator: Keycloak offers CredentialValidator
// authenticators only when the user has a stored credential of that type
// (AuthenticationSelectionResolver), which would bypass configuredFor() and
// make attribute-only users unselectable.
public class SmsAuthenticator implements Authenticator {

	private static final Logger logger = Logger.getLogger(SmsAuthenticator.class);
	static final String TPL_CODE = "login-sms.ftl";

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		AuthenticatorConfigModel config = context.getAuthenticatorConfig();
		KeycloakSession session = context.getSession();
		UserModel user = context.getUser();
		RealmModel realm = context.getRealm();

		String mobileNumber = resolveMobileNumber(config, user);
		if (mobileNumber == null) {
			logger.warnf("No mobile number available for user %s (no SMS credential and no attribute value)", user.getUsername());
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
				context.form().setError("smsAuthSmsNotSent", "Error. Use another method.")
					.createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
			return;
		}

		int length = Integer.parseInt(config.getConfig().get("length"));
		int ttl = Integer.parseInt(config.getConfig().get("ttl"));

		String code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		authSession.setAuthNote("code", code);
		authSession.setAuthNote("ttl", Long.toString(System.currentTimeMillis() + (ttl * 1000L)));

		try {
			Theme theme = session.theme().getTheme(Theme.Type.LOGIN);
			Locale locale = session.getContext().resolveLocale(user);
			String smsAuthText = theme.getEnhancedMessages(realm,locale).getProperty("smsAuthText");
			String smsText = String.format(smsAuthText, code, Math.floorDiv(ttl, 60));

			SmsServiceFactory.get(config.getConfig()).send(mobileNumber, smsText);

			context.challenge(context.form()
				.setAttribute("realm", realm)
				.setAttribute("phoneNumber", mobileNumber)
				.createForm(TPL_CODE));
		} catch (Exception e) {
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
				context.form().setError("smsAuthSmsNotSent", "Error. Use another method.")
					.createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
		}
	}

	@Override
	public void action(AuthenticationFlowContext context) {
		String enteredCode = context.getHttpRequest().getDecodedFormParameters().getFirst("code");

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
				context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
					context.form().setError("smsAuthCodeExpired").createErrorPage(Response.Status.BAD_REQUEST));
			} else {
				// valid
				context.success();
			}
		} else {
			// invalid
			String mobileNumber = resolveMobileNumber(context.getAuthenticatorConfig(), context.getUser());
			context.getEvent().user(context.getUser()).error("invalid_user_credentials");
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
		if (getCredentialProvider(session).isConfiguredFor(realm, user, SmsAuthCredentialModel.TYPE)) {
			return true;
		}
		// When storeInAttribute is active, a populated attribute (e.g. federated from
		// LDAP) is enough: the user can authenticate without an enrolled credential.
		// TODO: get the alias from somewhere else or move config into realm or application scope
		AuthenticatorConfigModel config = realm.getAuthenticatorConfigByAlias("sms-2fa");
		return isStoreInAttribute(config) && getAttributeNumber(config, user) != null;
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

	public SmsAuthCredentialProvider getCredentialProvider(KeycloakSession session) {
		return (SmsAuthCredentialProvider)session.getProvider(CredentialProvider.class, SmsAuthCredentialProviderFactory.PROVIDER_ID);
	}

	/**
	 * Resolve the number the code is sent to. The stored SMS credential is used when
	 * present. When storeInAttribute is active the user attribute is the source of
	 * truth: it wins over the credential, and a user whose attribute is already
	 * populated (e.g. via LDAP federation) needs no enrolled credential at all.
	 * Returns null when neither source has a number.
	 */
	static String resolveMobileNumber(AuthenticatorConfigModel config, UserModel user) {
		String credentialNumber = getCredentialNumber(user);
		if (!isStoreInAttribute(config)) {
			return credentialNumber;
		}
		String attributeNumber = getAttributeNumber(config, user);
		if (attributeNumber != null) {
			return attributeNumber;
		}
		if (credentialNumber != null) {
			logger.warnf("storeInAttribute is active but attribute '%s' is empty for user %s, falling back to credential value",
				getMobileNumberAttribute(config), user.getUsername());
		}
		return credentialNumber;
	}

	private static String getCredentialNumber(UserModel user) {
		Optional<CredentialModel> model = user.credentialManager()
			.getStoredCredentialsByTypeStream(SmsAuthCredentialModel.TYPE).findFirst();
		if (model.isEmpty()) {
			return null;
		}
		try {
			return JsonSerialization.readValue(model.get().getCredentialData(), SmsAuthCredentialData.class).getMobileNumber();
		} catch (IOException e) {
			logger.warn(e.getMessage(), e);
			return null;
		}
	}

	private static String getAttributeNumber(AuthenticatorConfigModel config, UserModel user) {
		return user.getAttributeStream(getMobileNumberAttribute(config))
			.filter(n -> n != null && !n.isBlank())
			.findFirst()
			.orElse(null);
	}

	private static boolean isStoreInAttribute(AuthenticatorConfigModel config) {
		return config != null && config.getConfig() != null
			&& Boolean.parseBoolean(config.getConfig().getOrDefault("storeInAttribute", "false"));
	}

	private static String getMobileNumberAttribute(AuthenticatorConfigModel config) {
		return config.getConfig().getOrDefault("mobileNumberAttribute", "mobile_number");
	}
}
