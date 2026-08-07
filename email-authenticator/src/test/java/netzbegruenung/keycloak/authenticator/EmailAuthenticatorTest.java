/*
 * Copyright 2026 tech@spree GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package netzbegruenung.keycloak.authenticator;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailSenderProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.ThemeManager;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.matches;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class EmailAuthenticatorTest {

	private EmailAuthenticator authenticator;
	private AuthenticationFlowContext context;
	private AuthenticationSessionModel authSession;
	private HttpRequest request;
	private LoginFormsProvider form;
	private RealmModel realm;
	private KeycloakSession session;
	private KeycloakContext keycloakContext;
	private UserModel user;
	private EmailSenderProvider emailSenderProvider;

	@BeforeEach
	public void setup() throws Exception {
		authenticator = new EmailAuthenticator();
		context = mock(AuthenticationFlowContext.class);
		authSession = mock(AuthenticationSessionModel.class);
		request = mock(HttpRequest.class);
		form = mock(LoginFormsProvider.class);
		realm = mock(RealmModel.class);
		session = mock(KeycloakSession.class);
		keycloakContext = mock(KeycloakContext.class);
		user = mock(UserModel.class);
		emailSenderProvider = mock(EmailSenderProvider.class);

		when(context.getAuthenticationSession()).thenReturn(authSession);
		when(context.getHttpRequest()).thenReturn(request);
		when(context.form()).thenReturn(form);
		when(context.getRealm()).thenReturn(realm);
		when(context.getSession()).thenReturn(session);
		when(context.getUser()).thenReturn(user);

		when(session.getProvider(EmailSenderProvider.class)).thenReturn(emailSenderProvider);
		when(session.getContext()).thenReturn(keycloakContext);
		when(keycloakContext.resolveLocale(user)).thenReturn(Locale.ENGLISH);

		ThemeManager themeManager = mock(ThemeManager.class);
		Theme theme = mock(Theme.class);
		when(session.theme()).thenReturn(themeManager);
		when(themeManager.getTheme(Theme.Type.LOGIN)).thenReturn(theme);
		Properties messages = new Properties();
		messages.setProperty("emailAuthSubject", "Your login code");
		messages.setProperty("emailAuthText", "Code: %1$s valid %2$d min");
		when(theme.getEnhancedMessages(eq(realm), any(Locale.class))).thenReturn(messages);

		when(user.getEmail()).thenReturn("test@example.com");
		when(user.isEmailVerified()).thenReturn(true);

		when(form.setAttribute(anyString(), any())).thenReturn(form);
		when(form.setError(anyString(), any())).thenReturn(form);
		when(form.setError(anyString(), (Object[]) any())).thenReturn(form);
		when(form.setError(anyString())).thenReturn(form);
		when(form.createForm(anyString())).thenReturn(mock(Response.class));
	}

	@Test
	public void testAction_Success() {
		when(authSession.getAuthNote("code")).thenReturn("123456");
		when(authSession.getAuthNote("ttl")).thenReturn(String.valueOf(System.currentTimeMillis() + 60000));

		MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
		params.add("code", "123456");
		when(request.getDecodedFormParameters()).thenReturn(params);

		authenticator.action(context);

		verify(context).success();
	}

	@Test
	public void testAction_InvalidCode() {
		AuthenticationExecutionModel execution = mock(AuthenticationExecutionModel.class);
		when(context.getExecution()).thenReturn(execution);
		when(execution.isRequired()).thenReturn(true);

		when(authSession.getAuthNote("code")).thenReturn("123456");
		when(authSession.getAuthNote("ttl")).thenReturn(String.valueOf(System.currentTimeMillis() + 60000));

		MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
		params.add("code", "654321");
		when(request.getDecodedFormParameters()).thenReturn(params);

		authenticator.action(context);

		verify(context).failureChallenge(eq(AuthenticationFlowError.INVALID_CREDENTIALS), any());
	}

	@Test
	public void testAction_ExpiredCode() {
		when(authSession.getAuthNote("code")).thenReturn("123456");
		when(authSession.getAuthNote("ttl")).thenReturn(String.valueOf(System.currentTimeMillis() - 1000));

		MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
		params.add("code", "123456");
		when(request.getDecodedFormParameters()).thenReturn(params);

		authenticator.action(context);

		verify(context).failureChallenge(eq(AuthenticationFlowError.EXPIRED_CODE), any());
	}

	@Test
	public void testAuthenticate_SendsEmail() throws EmailException {
		AuthenticatorConfigModel config = new AuthenticatorConfigModel();
		Map<String, String> configMap = new HashMap<>();
		configMap.put("length", "6");
		configMap.put("ttl", "300");
		config.setConfig(configMap);

		when(context.getAuthenticatorConfig()).thenReturn(config);

		authenticator.authenticate(context);

		verify(emailSenderProvider).send(any(), eq(user), eq("Your login code"), matches("Code: \\d{6} valid 5 min"), matches("Code: \\d{6} valid 5 min"));
	}
}
