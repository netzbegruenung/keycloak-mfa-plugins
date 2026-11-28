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
 * @author Niko Köbler, https://www.n-k.de, @dasniko
 * @author Netzbegruenung e.V.
 * @author verdigado eG
 *
 * Modified by B-Sharpe, 2026: phone numbers masked in logs.
 */

package netzbegruenung.keycloak.authenticator.gateway;

import java.util.Map;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.Builder;
import java.net.http.HttpResponse;
import org.jboss.logging.Logger;
import java.util.Base64;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;

public class ApiSmsService implements SmsService{

	private static final Logger logger = Logger.getLogger(SmsServiceFactory.class);
	private static final Pattern nonDigitPattern = Pattern.compile("[^0-9+]");

	private final String apiurl;
	private final Boolean urlencode;

	private final Boolean apiTokenInHeader;
	private final String apitoken;
	private final String apiuser;

	private final String senderId;
	private final String countrycode;

	private final String apitokenattribute;
	private final String messageattribute;
	private final String receiverattribute;
	private final String receiverJsonTemplate;
	private final String senderattribute;
	private final Boolean useUuid;
	private final String uuidAttribute;

	private final String jsonTemplate;

	private final boolean hideResponsePayload;

	private final String getUrl;

	private final boolean stripPlusPrefix;

	private final boolean stripFormattingCharacters;

	ApiSmsService(Map<String, String> config) {
		apiurl = config.get("apiurl");
		urlencode = Boolean.parseBoolean(config.getOrDefault("urlencode", "false"));

		apiTokenInHeader = Boolean.parseBoolean(config.getOrDefault("apiTokenInHeader", "false"));
		apitoken = config.getOrDefault("apitoken", "");
		apiuser = config.getOrDefault("apiuser", "");

		countrycode = config.getOrDefault("countrycode", "");
		senderId = config.get("senderId");

		apitokenattribute = config.getOrDefault("apitokenattribute", "");
		messageattribute = config.get("messageattribute");
		receiverattribute = config.get("receiverattribute");
		receiverJsonTemplate = config.getOrDefault("receiverJsonTemplate", "\"%s\"");
		senderattribute = config.get("senderattribute");
		useUuid = Boolean.parseBoolean(config.getOrDefault("useUuid", "false"));
		uuidAttribute = config.getOrDefault("uuidAttribute", "");

		jsonTemplate = config.getOrDefault("jsonTemplate", "");

		hideResponsePayload = Boolean.parseBoolean(config.get("hideResponsePayload"));

		getUrl = config.getOrDefault("getUrl", "");

		stripPlusPrefix = Boolean.parseBoolean(config.getOrDefault("stripPlusPrefix", "false"));

		stripFormattingCharacters = Boolean.parseBoolean(config.getOrDefault("stripFormattingCharacters", "true"));
	}

	public void send(String phoneNumber, String message) {
		if (stripFormattingCharacters) {
			phoneNumber = removeFormattingCharacters(phoneNumber);
		}
		phoneNumber = PhoneNumberNormalizer.toE164(phoneNumber, countrycode);
		if (stripPlusPrefix && phoneNumber.startsWith("+")) {
			phoneNumber = phoneNumber.substring(1);
		}
		Builder requestBuilder;
		HttpRequest request = null;
		String requestPayload = null;
		var client = HttpClient.newHttpClient();
		try {
			if (getUrl != null && !getUrl.isBlank()) {
				requestBuilder = getRequest(phoneNumber, message);
			} else {
				if (urlencode) {
					requestBuilder = urlencodedRequest(phoneNumber, message);
				} else {
					requestPayload = getJsonBody(phoneNumber, message);
					requestBuilder = jsonRequest(requestPayload);
				}
			}

			if (apiTokenInHeader) {
				String headerName = (apitokenattribute != null && !apitokenattribute.isEmpty())
					? apitokenattribute
					: "Authorization";
				request = requestBuilder.setHeader(headerName, apitoken).build();
			}else if (apiuser != null && !apiuser.isEmpty()) {
				request = requestBuilder.setHeader("Authorization", getAuthHeader(apiuser, apitoken)).build();
			} else {
				request = requestBuilder.build();
			}
			HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

			int statusCode = response.statusCode();
			String payload = hideResponsePayload ? "redacted" : "Response: " + response.body();

			// The HTTP client only returns final responses (>= 200): a 2xx class check is all it takes.
			if (statusCode / 100 == 2) {
				logger.infof("Sent SMS to %s [%s]", PhoneNumberMasker.mask(phoneNumber), payload);
			} else {
				logErrorStatus(phoneNumber, payload, request, statusCode);
			}
		} catch (Exception e) {
			logErrorException(phoneNumber, request);
		}
	}

	// The request payload is deliberately not logged: it contains the one-time code. For the same reason
	// only the method and the server of the request are logged (see describe).
	private void logErrorStatus(String phoneNumber, String responsePayload, HttpRequest request, int statusCode) {
		logger.errorf("Failed to send message to %s [%s] with request: %s [Status: %s]. Validate your config.",
			PhoneNumberMasker.mask(phoneNumber), responsePayload, describe(request), statusCode);
	}

	private void logErrorException(String phoneNumber, HttpRequest request) {
		logger.errorf("Failed to send message to %s with request: %s. Validate your config.",
			PhoneNumberMasker.mask(phoneNumber), describe(request));
	}

	/**
	 * Method and server only: the path and query of a GET request carry the number and the message (with
	 * the code), and the URI's user info can carry credentials.
	 */
	private static String describe(HttpRequest request) {
		if (request == null) {
			return "null";
		}
		URI uri = request.uri();
		String port = uri.getPort() == -1 ? "" : ":" + uri.getPort();
		return request.method() + " " + uri.getScheme() + "://" + uri.getHost() + port;
	}

	private String getJsonBody(String phoneNumber, String message) {
		if (!jsonTemplate.isBlank()) {
			return useUuid ?
				String.format(jsonTemplate, UUID.randomUUID(), phoneNumber, message) :
				String.format(jsonTemplate, phoneNumber, message);
		}

		StringBuilder json = new StringBuilder("{");
		boolean firstField = true;

		if (!apiTokenInHeader && apitokenattribute != null && !apitokenattribute.isEmpty()) {
			json.append(String.format("\"%s\":\"%s\"", apitokenattribute, apitoken));
			firstField = false;
		}

		if (useUuid) {
			if (!firstField) json.append(",");
			json.append(String.format("\"%s\":\"%s\"", uuidAttribute, UUID.randomUUID()));
			firstField = false;
		}

		if (!firstField) json.append(",");
		json.append(String.format("\"%s\":\"%s\"", messageattribute, message));

		json.append(",").append(String.format("\"%s\":%s", receiverattribute, String.format(receiverJsonTemplate, phoneNumber)));
		json.append(",").append(String.format("\"%s\":\"%s\"", senderattribute, senderId));
		json.append("}");

		return json.toString();
	}

	public Builder jsonRequest(String sendJson) {
		return HttpRequest.newBuilder()
			.uri(URI.create(apiurl))
			.header("Content-Type", "application/json")
			.POST(HttpRequest.BodyPublishers.ofString(sendJson));
	}


	public Builder urlencodedRequest(String phoneNumber, String message) {
		String body = (apiTokenInHeader ? "" : Optional.ofNullable(apitokenattribute)
						  .map(it -> String.format("%s=%s&", it, URLEncoder.encode(apitoken, Charset.defaultCharset()))).orElse(""))
					  + (useUuid ? String.format("%s=%s&", uuidAttribute, URLEncoder.encode(UUID.randomUUID().toString(), Charset.defaultCharset())) : "")
					  + String.format("%s=%s&", messageattribute, URLEncoder.encode(message, Charset.defaultCharset()))
					  + String.format("%s=%s&", receiverattribute, URLEncoder.encode(phoneNumber, Charset.defaultCharset()))
					  + String.format("%s=%s", senderattribute, URLEncoder.encode(senderId, Charset.defaultCharset()));

		return HttpRequest.newBuilder()
				.uri(URI.create(apiurl))
				.header("Content-Type", "application/x-www-form-urlencoded")
				.POST(HttpRequest.BodyPublishers.ofString(body));
	}

	public Builder getRequest(String phoneNumber, String message) {
		String getNewUrl = getUrl.replace("{phone}", URLEncoder.encode(phoneNumber, StandardCharsets.UTF_8));
		getNewUrl = getNewUrl.replace("{message}", URLEncoder.encode(message, StandardCharsets.UTF_8));
		getNewUrl = getNewUrl.replace("{apitoken}", URLEncoder.encode(apitoken, StandardCharsets.UTF_8));
		getNewUrl = getNewUrl.replace("{senderId}", URLEncoder.encode(senderId != null ? senderId : "", StandardCharsets.UTF_8));
		return HttpRequest.newBuilder()
				.uri(URI.create(apiurl.concat(getNewUrl)))
				.GET();
	}

	private static String getAuthHeader(String apiuser, String apitoken) {
		String authString = apiuser + ':' + apitoken;
		String b64_cred = Base64.getEncoder().encodeToString(authString.getBytes());
		return "Basic " + b64_cred;
	}

	private static String removeFormattingCharacters(String phone_number) {
		/*
		 * Remove everything that is not a digit or a plus sign, e.g. spaces, non-breaking spaces,
		 * dashes and parentheses. Numbers taken from a user attribute never pass through the phone
		 * number required action, so this is the only place that sees every send path.
		 * PhoneNumberNormalizer ignores formatting too, but returns the number verbatim when no
		 * default country code is configured or the number cannot be parsed.
		 */
		if (phone_number == null) {
			return null;
		}
		String stripped = nonDigitPattern.matcher(phone_number).replaceAll("");
		if (!stripped.equals(phone_number)) {
			logger.infof("Clean phone number: stripped formatting characters, set phone number to %s",
				PhoneNumberMasker.mask(stripped));
		}
		return stripped;
	}
}
