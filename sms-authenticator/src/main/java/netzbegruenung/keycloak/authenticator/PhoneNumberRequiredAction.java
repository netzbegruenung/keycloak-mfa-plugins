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
 */

package netzbegruenung.keycloak.authenticator;

import com.google.common.base.Splitter;
import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import com.google.i18n.phonenumbers.Phonenumber.PhoneNumber;
import jakarta.ws.rs.core.Response;
import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialModel;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.CredentialRegistrator;
import org.keycloak.authentication.InitiatedActionSupport;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.authentication.requiredactions.WebAuthnRegisterFactory;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.HashSet;
import java.util.Set;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.theme.Theme;

import java.net.URI;

import jakarta.ws.rs.core.UriBuilder;

public class PhoneNumberRequiredAction implements RequiredActionProvider, CredentialRegistrator {

	public static final String PROVIDER_ID = "mobile_number_config";

	private static final Logger logger = Logger.getLogger(PhoneNumberRequiredAction.class);
	private static final Splitter numberFilterSplitter = Splitter.on("##");
	private static final Pattern nonDigitPattern = Pattern.compile("[^0-9+]");
	private static final Pattern whitespacePattern = Pattern.compile("\\s+");

	@Override
	public InitiatedActionSupport initiatedActionSupport() {
		return InitiatedActionSupport.SUPPORTED;
	}

	@Override
	public void evaluateTriggers(RequiredActionContext context) {
		// TODO: get the alias from somewhere else or move config into realm or application scope
		AuthenticatorConfigModel config = context.getRealm().getAuthenticatorConfigByAlias("sms-2fa");
		if (config == null) {
			logger.error("Failed to check 2FA enforcement, no config alias sms-2fa found");
			return;
		}
		boolean forceSecondFactorEnabled = Boolean.parseBoolean(config.getConfig().get("forceSecondFactor"));
		if (forceSecondFactorEnabled) {
			if (config.getConfig().get("whitelist") != null) {
				RoleModel whitelistRole = context.getRealm().getRole(config.getConfig().get("whitelist"));
				if (whitelistRole == null) {
					logger.errorf(
						"Failed configured whitelist role check [%s], make sure that the role exists",
						config.getConfig().get("whitelist")
					);
				} else if (context.getUser().hasRole(whitelistRole)) {
					// skip enforcement if user is whitelisted
					return;
				}
			}
			// add auth note for phone number input placeholder
			context.getAuthenticationSession().setAuthNote("mobileInputFieldPlaceholder",
				config.getConfig().getOrDefault("mobileInputFieldPlaceholder", ""));

			// list of accepted 2FA alternatives
			List<String> secondFactors = Arrays.asList(
				SmsAuthCredentialModel.TYPE,
				WebAuthnCredentialModel.TYPE_TWOFACTOR,
				OTPCredentialModel.TYPE
			);
			Stream<CredentialModel> credentials = context
				.getUser()
				.credentialManager()
				.getStoredCredentialsStream();
			if (credentials.anyMatch(x -> secondFactors.contains(x.getType()))) {
				// skip as 2FA is already set
				return;
			}

			Set<String> availableRequiredActions = Set.of(
				PhoneNumberRequiredAction.PROVIDER_ID,
				PhoneValidationRequiredAction.PROVIDER_ID,
				UserModel.RequiredAction.CONFIGURE_TOTP.name(),
				WebAuthnRegisterFactory.PROVIDER_ID,
				UserModel.RequiredAction.UPDATE_PASSWORD.name()
			);
			// Merge user + session queues: phone_validation often sits only on the session queue (e.g. after number submit).
			// Session-only checks used to re-queue mobile_number in evaluateTriggers and show the phone step twice.
			Set<String> mfaRequiredActionsPending = new HashSet<>(context.getAuthenticationSession().getRequiredActions());
			context.getUser().getRequiredActionsStream().forEach(mfaRequiredActionsPending::add);
			mfaRequiredActionsPending.retainAll(availableRequiredActions);
			if (!mfaRequiredActionsPending.isEmpty()) {
				return;
			}

			logger.infof(
				"No 2FA method configured for user: %s, setting required action for SMS authenticator",
				context.getUser().getUsername()
			);
			context.getUser().addRequiredAction(PhoneNumberRequiredAction.PROVIDER_ID);
		}
	}

	/**
	 * Generates a list of country codes with their names and emojis to be displayed in the phone number input form.
	 *
	 * @param context the current RequiredActionContext
	 * @return a list of maps containing country name, code, and emoji
	 */
	public List<Map<String, String>> getCountryCodeList(RequiredActionContext context) {
		AuthenticatorConfigModel config = context.getRealm().getAuthenticatorConfigByAlias("sms-2fa");
		String countryCodeList = config.getConfig().getOrDefault("countryCodeList", "");

		UserModel user = context.getUser();
		KeycloakSession session = context.getSession();
		Locale locale = session.getContext().resolveLocale(user);

		PhoneNumberUtil phoneUtil = PhoneNumberUtil.getInstance();

		List<Map<String, String>> countryList = new ArrayList<>();
		if (!countryCodeList.isBlank()) {
			List<String> countryCodes = Arrays.asList(countryCodeList.split(","));
			for (String countryCode : countryCodes) {
				try {
					String code = "+" + Integer.toString(phoneUtil.getCountryCodeForRegion(countryCode.trim().toUpperCase()));
					String countryName = new Locale("", countryCode.trim().toUpperCase()).getDisplayCountry(locale);

					// generate emoji from country code
					int offset = 0x1F1E6;  // Base Unicode for regional indicator symbols
					int codePoint1 = offset + (countryCode.trim().toUpperCase().charAt(0) - 'A');
					int codePoint2 = offset + (countryCode.trim().toUpperCase().charAt(1) - 'A');
					String emoji = new String(new int[]{codePoint1, codePoint2}, 0, 2);

					countryList.add(Map.of("name", countryName, "code", code, "emoji", emoji));
					logger.infof("Added country code %s for country %s", code, countryName);
				} catch (Exception e) {
					logger.errorf("Failed to get country code for country %s", countryCode, e);
				}
			}
		}

		return countryList;
	}

	/**
	 * Same contract as Keycloak's {@code RequiredActionContextResult#getActionUrl(String)}: first arg is the
	 * client session code, not a provider id. {@code execution} is set explicitly (server always uses the current action).
	 */
	private static URI buildRequiredActionFormUri(
		RequiredActionContext context,
		String clientSessionCode,
		String executionProviderId) {
		UriBuilder b = LoginActionsService.requiredActionProcessor(context.getUriInfo());
		b.queryParam(LoginActionsService.SESSION_CODE, clientSessionCode);
		b.queryParam("execution", executionProviderId);
		ClientModel client = context.getAuthenticationSession().getClient();
		if (client != null) {
			b.queryParam("client_id", client.getClientId());
		} else {
			String cid = context.getUriInfo().getQueryParameters().getFirst("client_id");
			if (cid != null) {
				b.queryParam("client_id", cid);
			}
		}
		String tabId = context.getAuthenticationSession().getTabId();
		if (tabId == null) {
			tabId = context.getUriInfo().getQueryParameters().getFirst("tab_id");
		}
		if (tabId != null) {
			b.queryParam("tab_id", tabId);
		}
		String clientData = AuthenticationProcessor.getClientData(
			context.getSession(),
			context.getAuthenticationSession()
		);
		if (clientData == null) {
			clientData = context.getUriInfo().getQueryParameters().getFirst("client_data");
		}
		if (clientData != null) {
			b.queryParam("client_data", clientData);
		}
		return b.build(context.getRealm().getName());
	}

	/**
	 * Return to the phone step from SMS validation: issues a fresh {@code session_code} (required; reusing the old
	 * one yields Keycloak's "Page has expired"). Does not use {@link #buildPhoneNumberForm(RequiredActionContext, URI)}
	 * because {@code context.form()} would mint another code and desync the form action URL.
	 */
	public void showPhoneNumberFormAfterChangeNumber(RequiredActionContext context) {
		// Keep current execution in sync with the shown form; otherwise getLastExecutionUrl / replaceState can keep
		// phone_validation while the next GET mixes validation URL with the phone UI / RA queue.
		context.getAuthenticationSession().setAuthNote(
			AuthenticationProcessor.CURRENT_AUTHENTICATION_EXECUTION,
			PROVIDER_ID
		);
		String code = context.generateCode();
		URI action = buildRequiredActionFormUri(context, code, PROVIDER_ID);
		LoginFormsProvider form = context
			.getSession()
			.getProvider(LoginFormsProvider.class)
			.setAuthenticationSession(context.getAuthenticationSession())
			.setUser(context.getUser())
			.setActionUri(action)
			.setExecution(PROVIDER_ID)
			.setClientSessionCode(code)
			.setAttribute(
				"mobileInputFieldPlaceholder",
				context.getAuthenticationSession().getAuthNote("mobileInputFieldPlaceholder")
			)
			.setAttribute("countryList", getCountryCodeList(context));
		context.challenge(form.createForm("mobile_number_form.ftl"));
	}

	/**
	 * Localized line for the code screen: shows the exact destination used for the SMS (same string as in session / send path).
	 */
	public static String buildSmsDestinationHint(
		KeycloakSession session,
		RealmModel realm,
		UserModel user,
		String rawDestination) {
		if (rawDestination == null || rawDestination.isBlank()) {
			return null;
		}
		try {
			Theme theme = session.theme().getTheme(Theme.Type.LOGIN);
			Locale locale = session.getContext().resolveLocale(user);
			String pattern = theme.getEnhancedMessages(realm, locale).getProperty("smsAuthSentTo");
			if (pattern == null) {
				pattern = "The code was sent to %1$s";
			}
			return String.format(pattern, rawDestination);
		} catch (Exception e) {
			return rawDestination;
		}
	}

	/**
	 * Phone number form; when {@code formAction} is set, POST targets that URL (e.g. return from code validation).
	 */
	Response buildPhoneNumberForm(RequiredActionContext context, java.net.URI formAction) {
		LoginFormsProvider form = context.form()
			.setAttribute("mobileInputFieldPlaceholder", context.getAuthenticationSession().getAuthNote("mobileInputFieldPlaceholder"))
			.setAttribute("countryList", getCountryCodeList(context));
		if (formAction != null) {
			form = form.setActionUri(formAction);
		}
		return form.createForm("mobile_number_form.ftl");
	}

	/** Shows the phone number form; optional custom form action URL. */
	public void showPhoneNumberForm(RequiredActionContext context, java.net.URI formAction) {
		context.challenge(buildPhoneNumberForm(context, formAction));
	}

	@Override
	public void requiredActionChallenge(RequiredActionContext context) {
		context.challenge(buildPhoneNumberForm(context, null));
	}

	@Override
	public void processAction(RequiredActionContext context) {
		String enrollment = context.getHttpRequest().getDecodedFormParameters().getFirst(SmsEnrollmentAbandon.FORM_PARAM);
		if (SmsEnrollmentAbandon.ACTION_CANCEL.equals(enrollment)) {
			SmsEnrollmentAbandon.abandonAndRedirect(context);
			return;
		}

		String mobileRaw = context.getHttpRequest().getDecodedFormParameters().getFirst("mobile_number");
		if (mobileRaw == null) {
			requiredActionChallenge(context);
			return;
		}
		String mobileNumber = nonDigitPattern.matcher(mobileRaw).replaceAll("");
		AuthenticationSessionModel authSession = context.getAuthenticationSession();

		// get the country code from the select input if available and add it to the mobile number
		if (context.getHttpRequest().getDecodedFormParameters().getFirst("country_code") != null) {
			String countryCode = nonDigitPattern.matcher(context.getHttpRequest().getDecodedFormParameters().getFirst("country_code")).replaceAll("");
			mobileNumber = countryCode + mobileNumber.replaceAll("^0+", "");
		}

		// get the phone number formatting values from the config
		AuthenticatorConfigModel config = context.getRealm().getAuthenticatorConfigByAlias("sms-2fa");
		boolean normalizeNumber = false;
		boolean forceRetryOnBadFormat = false;
		if (config != null && config.getConfig() != null) {
			normalizeNumber = Boolean.parseBoolean(config.getConfig().getOrDefault("normalizePhoneNumber", "false"));
			forceRetryOnBadFormat = Boolean.parseBoolean(config.getConfig().getOrDefault("forceRetryOnBadFormat", "false"));
		}

		// try to format the phone number
		if (normalizeNumber) {
			String formattedNumber = formatPhoneNumber(context, mobileNumber);
			if (formattedNumber != null && !formattedNumber.isBlank()) {
				mobileNumber = formattedNumber;
			} else if (forceRetryOnBadFormat) {
				logger.errorf("Failed phone number formatting checks for: %s", mobileNumber);
				String formatError = context.getAuthenticationSession().getAuthNote("formatError");
				if (formatError != null && !formatError.isBlank()) {
					handleInvalidNumber(context, formatError);
					return;
				}
			}
		}

		authSession.setAuthNote("mobile_number", mobileNumber);
		logger.infof("Add required action for phone validation: [%s], user: %s", mobileNumber, context.getUser().getUsername());
		authSession.addRequiredAction(PhoneValidationRequiredAction.PROVIDER_ID);
		// Both queues: some GETs without session_code only see user-level RAs; otherwise evaluateTriggers can re-add
		// mobile_number and ordering puts the phone step ahead of the code step again.
		context.getUser().addRequiredAction(PhoneValidationRequiredAction.PROVIDER_ID);
		context.success();
	}

	/**
	 * Formats the provided mobile phone number to E164 standard.
	 *
	 * @param context		the current RequiredActionContext
	 * @param mobileNumber	the mobile phone number to be formatted
	 * @return				the formatted mobile phone number, null if the phone number is invalid or mobileNumber if the config was not found
	 */
	private String formatPhoneNumber(RequiredActionContext context, String mobileNumber) {
		AuthenticatorConfigModel config = context.getRealm().getAuthenticatorConfigByAlias("sms-2fa");
		if (config == null || config.getConfig() == null) {
			logger.error("Failed format phone number, no config alias sms-2fa found");
			return mobileNumber;
		}
		final PhoneNumberUtil phoneNumberUtil = PhoneNumberUtil.getInstance();
		int countryNumber;
		// try to get the country code from the country number in the config, fallback on default DE
		try {
			countryNumber = Integer.parseInt(whitespacePattern.matcher(config.getConfig()
				.getOrDefault("countrycode", "49").replace("+", ""))
				.replaceAll(""));
		} catch (NumberFormatException e) {
			logger.warn("Failed to parse countrycode to int, using default value (49)", e);
			countryNumber = 49;
		}
		String nameCodeToUse = phoneNumberUtil.getRegionCodeForCountryCode(countryNumber);
		PhoneNumber originalPhoneNumberParsed;

		// parse the mobile number and store it as instance of PhoneNumber
		try {
			originalPhoneNumberParsed = phoneNumberUtil.parse(mobileNumber, nameCodeToUse);
		} catch (NumberParseException e) {
			logger.error("Failed to parse phone number", e);
			context.getAuthenticationSession().setAuthNote("formatError", "numberFormatFailedToParse");
			return null;
		}

		if (!phoneNumberUtil.isValidNumber(originalPhoneNumberParsed)) {
			logger.error("Phone number is not valid");
			context.getAuthenticationSession().setAuthNote("formatError", "numberFormatNumberInvalid");
			return null;
		}

		// apply ValidNumberType filters
		// try to extract number types from filter string
		List<PhoneNumberUtil.PhoneNumberType> numberTypeFilters = new ArrayList<>();
		String numberFiltersString = null;
		try {
			numberFiltersString = config.getConfig().getOrDefault("numberTypeFilters", "");
			if (!numberFiltersString.isBlank()) {
				numberFilterSplitter.splitToStream(numberFiltersString).forEach(filterString ->
					numberTypeFilters.add(PhoneNumberUtil.PhoneNumberType.valueOf(filterString)));
			}
		} catch (Exception e) {
			// if the number type filter configuration is bad, log an error and continue without filtering
			logger.errorf("Illegal filter found: %s. Filter must be a list of comma delimited Strings of FIXED_LINE, MOBILE, "
				+ "FIXED_LINE_OR_MOBILE, PAGER, TOLL_FREE, PREMIUM_RATE, SHARED_COST, PERSONAL_NUMBER, VOIP, UAN, VOICEMAIL", numberFiltersString);
			numberTypeFilters.clear();
		}

		// check to see if the number type matches any of the filters set
		if (!numberTypeFilters.isEmpty()) {
			PhoneNumberUtil.PhoneNumberType numberType = phoneNumberUtil.getNumberType(originalPhoneNumberParsed);
			if (numberTypeFilters.stream().noneMatch(filter -> filter == numberType)) {
				logger.errorf("Phone number type %s does not match any filters in %s", numberType.toString(), numberTypeFilters);
				context.getAuthenticationSession().setAuthNote("formatError", "numberFormatNoMatchingFilters");
				return null;
			}
		}

		// return the E164 format of the mobile number
		return phoneNumberUtil.format(originalPhoneNumberParsed, PhoneNumberUtil.PhoneNumberFormat.E164);
	}

	private void handleInvalidNumber(RequiredActionContext context, String formatError) {
		Response challenge = context
			.form()
			.setAttribute("mobileInputFieldPlaceholder", context.getAuthenticationSession().getAuthNote("mobileInputFieldPlaceholder"))
			.setError(formatError)
			.createForm("mobile_number_form.ftl");
		context.challenge(challenge);
	}

	@Override
	public void close() {}

	@Override
	public String getCredentialType(KeycloakSession keycloakSession, AuthenticationSessionModel authenticationSessionModel) {
		return SmsAuthCredentialModel.TYPE;
	}
}
