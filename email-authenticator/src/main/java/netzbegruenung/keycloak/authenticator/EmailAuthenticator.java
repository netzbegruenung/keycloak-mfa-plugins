/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * Copyright 2026 tech@spree GmbH
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
 * @author tech@spree GmbH
 */

package netzbegruenung.keycloak.authenticator;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailSenderProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserModel.RequiredAction;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;

import jakarta.ws.rs.core.Response;
import java.util.Collections;
import java.util.Locale;
import java.util.Map;

public class EmailAuthenticator implements Authenticator {

	private static final Logger logger = Logger.getLogger(EmailAuthenticator.class);
	static final String TPL_CODE = "login-email.ftl";

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		AuthenticatorConfigModel config = context.getAuthenticatorConfig();
		KeycloakSession session = context.getSession();
		UserModel user = context.getUser();
		RealmModel realm = context.getRealm();

		Map<String, String> configMap = config != null ? config.getConfig() : Collections.emptyMap();

		if (user.getEmail() == null || !user.isEmailVerified()) {
			context.attempted();
			return;
		}

		int length = Integer.parseInt(configMap.getOrDefault("length", "6"));
		int ttl = Integer.parseInt(configMap.getOrDefault("ttl", "300"));

		String code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		authSession.setAuthNote("code", code);
		authSession.setAuthNote("ttl", Long.toString(System.currentTimeMillis() + (ttl * 1000L)));

		try {
			Theme theme = session.theme().getTheme(Theme.Type.LOGIN);
			Locale locale = session.getContext().resolveLocale(user);
			String subjectTemplate = theme.getEnhancedMessages(realm, locale).getProperty("emailAuthSubject");
			String bodyTemplate = theme.getEnhancedMessages(realm, locale).getProperty("emailAuthText");

			String subject = String.format(subjectTemplate, code, Math.floorDiv(ttl, 60));
			String body = String.format(bodyTemplate, code, Math.floorDiv(ttl, 60));

			EmailSenderProvider emailSenderProvider = session.getProvider(EmailSenderProvider.class);
			emailSenderProvider.send(realm.getSmtpConfig(), user, subject, body, body);

			context.challenge(context.form().setAttribute("realm", realm).createForm(TPL_CODE));
		} catch (EmailException | java.io.IOException e) {
			logger.warn("Failed to send verification email", e);
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
				context.form().setError("emailAuthEmailNotSent", e.getMessage())
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

		boolean isValid = code.equals(enteredCode);
		if (isValid) {
			if (Long.parseLong(ttl) < System.currentTimeMillis()) {
				context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
					context.form().setError("emailAuthCodeExpired").createForm(TPL_CODE));
			} else {
				context.success();
			}
		} else {
			AuthenticationExecutionModel execution = context.getExecution();
			if (execution.isRequired()) {
				context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
					context.form().setAttribute("realm", context.getRealm())
						.setError("emailAuthCodeInvalid").createForm(TPL_CODE));
			} else if (execution.isConditional() || execution.isAlternative()) {
				context.attempted();
			}
		}
	}

	@Override
	public boolean requiresUser() {
		return true;
	}

	@Override
	public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
		return user.getEmail() != null && user.isEmailVerified();
	}

	@Override
	public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
		if (user.getEmail() == null || !user.isEmailVerified()) {
			user.addRequiredAction(RequiredAction.VERIFY_EMAIL);
		}
	}

	@Override
	public void close() {
	}
}
