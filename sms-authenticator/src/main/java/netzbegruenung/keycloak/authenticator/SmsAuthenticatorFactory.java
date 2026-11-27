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
 * @author Netzbegruenung e.V.
 * @author verdigado eG
 * @author Niko Köbler, https://www.n-k.de, @dasniko
 */

package netzbegruenung.keycloak.authenticator;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import netzbegruenung.keycloak.authenticator.verification.GenericSmsVerificationProviderFactory;
import netzbegruenung.keycloak.authenticator.verification.SmsVerification;
import netzbegruenung.keycloak.authenticator.verification.SmsVerificationProvider;
import netzbegruenung.keycloak.authenticator.verification.SmsVerificationProviderFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

public class SmsAuthenticatorFactory implements AuthenticatorFactory {

	public static final String PROVIDER_ID = "mobile-number-authenticator";
	private static final SmsAuthenticator SINGLETON = new SmsAuthenticator();

	private volatile KeycloakSessionFactory sessionFactory;


	@Override
	public String getId() {
		return PROVIDER_ID;
	}

	@Override
	public Authenticator create(KeycloakSession session) {
		return SINGLETON;
	}

	private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
		AuthenticationExecutionModel.Requirement.REQUIRED,
		AuthenticationExecutionModel.Requirement.ALTERNATIVE,
		AuthenticationExecutionModel.Requirement.DISABLED
	};
	@Override
	public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
		return REQUIREMENT_CHOICES;
	}

	@Override
	public boolean isConfigurable() {
		return true;
	}

	@Override
	public boolean isUserSetupAllowed() {
		return true;
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		List<SmsVerificationProviderFactory> verificationProviders = getVerificationProviderFactories();

		ProviderConfigProperty provider = new ProviderConfigProperty(SmsVerification.CONFIG_PROVIDER, "SMS verification provider",
			"How the code is sent and verified. 'generic' generates the code in Keycloak and sends it with the configurable HTTP API. "
				+ "Only the settings of the selected provider are used.",
			ProviderConfigProperty.LIST_TYPE, GenericSmsVerificationProviderFactory.PROVIDER_ID);
		provider.setOptions(verificationProviders.stream().map(SmsVerificationProviderFactory::getId).toList());

		List<ProviderConfigProperty> properties = new ArrayList<>(List.of(
			new ProviderConfigProperty("length", "Code length", "The number of digits of the generated code.", ProviderConfigProperty.STRING_TYPE, 6),
			new ProviderConfigProperty("ttl", "Time-to-live", "The time to live in seconds for the code to be valid.", ProviderConfigProperty.STRING_TYPE, "300"),
			new ProviderConfigProperty("countrycode", "Default country prefix", "Default country prefix that is assumed if user does not provide one.", ProviderConfigProperty.STRING_TYPE, "+49"),
			provider
		));
		verificationProviders.forEach(factory -> properties.addAll(factory.getConfigProperties()));
		properties.addAll(List.of(
			new ProviderConfigProperty("forceSecondFactor", "Force 2FA", "If 2FA authentication is not configured, the user is forced to setup SMS Authentication.", ProviderConfigProperty.BOOLEAN_TYPE, false),
			new ProviderConfigProperty("whitelist", "Excluded from enforced 2FA", "All users with the here selected role are not forced to setup 2FA.", ProviderConfigProperty.ROLE_TYPE, null),
			new ProviderConfigProperty("enableByDefault", "Enable 2FA by default", "If enabled, users who have the configured mobile number attribute will have SMS 2FA activated automatically without any manual setup required.", ProviderConfigProperty.BOOLEAN_TYPE, false),
			new ProviderConfigProperty("mobileNumberAttribute", "Mobile number user attribute", "Name of the user attribute containing the mobile phone number used for auto-enrollment when 'Enable 2FA by default' is active.", ProviderConfigProperty.STRING_TYPE, "mobile_number"),
			new ProviderConfigProperty("mobileInputFieldPlaceholder", "Phone number input field placeholder", "The placeholder string user in the phone number input field", ProviderConfigProperty.STRING_TYPE, ""),
			new ProviderConfigProperty("storeInAttribute", "Set phone number as attribute", "Sets the phone number as a user attribute.", ProviderConfigProperty.BOOLEAN_TYPE, false),
			new ProviderConfigProperty("normalizePhoneNumber", "Format phone number", "Normalize the phone number using the E164 standard.", ProviderConfigProperty.BOOLEAN_TYPE, false),
			new ProviderConfigProperty("numberTypeFilters", "Valid number type filters", "A list of valid number types to filter the input phone number by. Possible values are: FIXED_LINE, MOBILE, "
				+ " FIXED_LINE_OR_MOBILE, PAGER, TOLL_FREE, PREMIUM_RATE, SHARED_COST, PERSONAL_NUMBER, VOIP, UAN, VOICEMAIL.", ProviderConfigProperty.MULTIVALUED_STRING_TYPE, Collections.emptyList()),
			new ProviderConfigProperty("forceRetryOnBadFormat", "Ask for new number if checks fail", "Sets an error message and asks the user to re-enter phone number if formatting checks are not successfully passed.", ProviderConfigProperty.BOOLEAN_TYPE, false),
			new ProviderConfigProperty("enforcePhoneNumberUniqueness", "Enforce phone number uniqueness", "If enabled, prevents users from registering a phone number that is already in use by another user.", ProviderConfigProperty.BOOLEAN_TYPE, true),
			new ProviderConfigProperty("countryCodeList", "List of country code", "Sets the list of country code in a select input to display to the user the supported countries. List separated by commas (ex : FR,DE,GB)", ProviderConfigProperty.STRING_TYPE, "")
		));
		return properties;
	}

	/**
	 * The generic provider first, so that its settings stay where they have always been,
	 * then all others ordered by id.
	 */
	private List<SmsVerificationProviderFactory> getVerificationProviderFactories() {
		if (sessionFactory == null) {
			return List.of(new GenericSmsVerificationProviderFactory());
		}
		return sessionFactory.getProviderFactoriesStream(SmsVerificationProvider.class)
			.map(SmsVerificationProviderFactory.class::cast)
			.sorted(Comparator
				.comparing((SmsVerificationProviderFactory factory) -> !GenericSmsVerificationProviderFactory.PROVIDER_ID.equals(factory.getId()))
				.thenComparing(SmsVerificationProviderFactory::getId))
			.toList();
	}

	@Override
	public String getHelpText() {
		return "Validates an OTP sent via SMS to the users mobile phone.";
	}

	@Override
	public String getDisplayType() {
		return "SMS Authentication (2FA)";
	}

	@Override
	public String getReferenceCategory() {
		return "mobile-number";
	}

	@Override
	public void init(Config.Scope config) {
	}

	@Override
	public void postInit(KeycloakSessionFactory factory) {
		this.sessionFactory = factory;
	}

	@Override
	public void close() {
	}

}
