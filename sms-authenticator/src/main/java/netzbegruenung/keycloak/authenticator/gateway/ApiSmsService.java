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
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;

public class ApiSmsService implements SmsService{

	private static final Logger logger = Logger.getLogger(SmsServiceFactory.class);
	private static final Pattern plusPrefixPattern = Pattern.compile("\\+");

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
	}

	public void send(String phoneNumber, String message) {
		phoneNumber = cleanPhoneNumber(phoneNumber, countrycode);
		Builder requestBuilder;
		HttpRequest request = null;
		String requestPayload = null;
		var client = HttpClient.newHttpClient();
		try {
			if (urlencode) {
				requestBuilder = urlencodedRequest(phoneNumber, message);
			} else {
				requestPayload = getJsonBody(phoneNumber, message);
				requestBuilder = jsonRequest(requestPayload);
			}

			if (apiTokenInHeader) {
				request = requestBuilder.setHeader("Authorization", apitoken).build();
			}else if (apiuser != null && !apiuser.isEmpty()) {
				request = requestBuilder.setHeader("Authorization", getAuthHeader(apiuser, apitoken)).build();
			} else {
				request = requestBuilder.build();
			}
			HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

			int statusCode = response.statusCode();
			String payload = hideResponsePayload ? "redacted" : "Response: " + response.body();

			if (statusCode >= 200 && statusCode < 300) {
				logger.infof("Sent SMS to %s [%s]", phoneNumber, payload);
			} else {
				logErrorStatus(phoneNumber, payload, request, requestPayload, statusCode);
			}
		} catch (Exception e) {
			logErrorException(phoneNumber, request, requestPayload);
		}
	}

	private void logErrorStatus(String phoneNumber, String responsePayload, HttpRequest request, String requestPayload, int statusCode) {
		String logMessage = "Failed to send message to %s [%s] with request: %s [Status: %s]";
		Object[] logParams = new Object[]{phoneNumber, responsePayload, request != null ? request.toString() : "null", statusCode};

		if (!urlencode && requestPayload != null) {
			logMessage += ". Payload: %s";
			logParams = new Object[]{phoneNumber, responsePayload, request != null ? request.toString() : "null", statusCode, requestPayload};
		}
		logMessage += ". Validate your config.";
		logger.errorf(logMessage, logParams);
	}

	private void logErrorException(String phoneNumber, HttpRequest request, String requestPayload) {
		String logMessage = "Failed to send message to %s with request: %s";
		Object[] logParams = new Object[]{phoneNumber, request != null ? request.toString() : "null"};

		if (!urlencode && requestPayload != null) {
			logMessage += ". Payload: %s";
			logParams = new Object[]{phoneNumber, request != null ? request.toString() : "null", requestPayload};
		}
		logMessage += ". Validate your config.";
		logger.errorf(logMessage, logParams);
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

	private static String getAuthHeader(String apiuser, String apitoken) {
		String authString = apiuser + ':' + apitoken;
		String b64_cred = Base64.getEncoder().encodeToString(authString.getBytes());
		return "Basic " + b64_cred;
	}

	private static String cleanPhoneNumber(String phone_number, String countrycode) {
		/*
		 * This function tries to correct several common user errors. If there is no default country
		 * prefix, this function does not dare to touch the phone number.
		 * https://en.wikipedia.org/wiki/List_of_mobile_telephone_prefixes_by_country
		 */
		if (countrycode == null || countrycode.isEmpty()) {
			logger.infof("Clean phone number: no country code set, return %s", phone_number);
			return phone_number;
		}
		String country_number = plusPrefixPattern.matcher(countrycode).replaceFirst("");
		// convert 49 to +49
		if (phone_number.startsWith(country_number)) {
			phone_number = phone_number.replaceFirst(country_number, countrycode);
			logger.infof("Clean phone number: convert 49 to +49, set phone number to %s", phone_number);
		}
		// convert 0049 to +49
		if (phone_number.startsWith("00" + country_number)) {
			phone_number = phone_number.replaceFirst("00" + country_number, countrycode);
			logger.infof("Clean phone number: convert 0049 to +49, set phone number to %s", phone_number);
		}
		// convert +490176 to +49176
		if (phone_number.startsWith(countrycode + '0')) {
			phone_number = phone_number.replaceFirst("\\+" + country_number + '0', countrycode);
			logger.infof("Clean phone number: convert +490176 to +49176, set phone number to %s", phone_number);
		}
		// convert 0 to +49
		if (phone_number.startsWith("0")) {
			phone_number = phone_number.replaceFirst("0", countrycode);
			logger.infof("Clean phone number: convert 0 to +49, set phone number to %s", phone_number);
		}
		return phone_number;
	}
}
