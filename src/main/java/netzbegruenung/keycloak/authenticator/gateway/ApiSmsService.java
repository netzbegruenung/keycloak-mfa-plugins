package netzbegruenung.keycloak.authenticator.gateway;

import java.util.Map;
import java.util.HashMap;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.io.*;
import javax.json.*;
import org.jboss.logging.Logger;

/**
 * @author Netzbegrünung e.V.
 */
public class ApiSmsService implements SmsService{

	private final String apiurl;
	private final Boolean urlencode;

	private final String apitoken;
	private final String apiuser;

	private final String from;

	private final String apitokenattribute;
	private final String messageattribute;
	private final String receiverattribute;
	private final String senderattribute;

	private static final Logger LOG = Logger.getLogger(SmsServiceFactory.class);

	ApiSmsService(Map<String, String> config) {
		apiurl = config.get("apiurl");
		LOG.warn(String.format("Parsed apiurl: %s", apiurl));
		urlencode = Boolean.parseBoolean(config.getOrDefault("urlencode", "false"));
		LOG.warn(String.format("Parsed urlencode: %b", urlencode));

		apitoken = config.getOrDefault("apitoken", "");
		LOG.warn(String.format("Parsed apitoken: %s", apitoken));
		apiuser = config.getOrDefault("apiuser", "");
		LOG.warn(String.format("Parsed apiuser: %s", apiuser));

		from = config.get("senderId");
		LOG.warn(String.format("Parsed senderId: %s", from));

		apitokenattribute = config.getOrDefault("apitokenattribute", "");
		LOG.warn(String.format("Parsed apitokenattribute: %s", apitokenattribute));
		messageattribute = config.get("messageattribute");
		LOG.warn(String.format("Parsed messageattribute: %s", messageattribute));
		receiverattribute = config.get("receiverattribute");
		LOG.warn(String.format("Parsed receiverattribute: %s", receiverattribute));
		senderattribute = config.get("senderattribute");
		LOG.warn(String.format("Parsed senderattribute: %s", senderattribute));
	}

	public void send(String phoneNumber, String message) {
		
		if (urlencode) {
			LOG.warn("Trying to send URLENCODE");
			send_urlencoded(phoneNumber, message);
			LOG.warn(String.format("Trying to send %s to %s via URL encoded request", message, phoneNumber));
		} else {
			LOG.warn("Trying to send JSON");
			send_json(phoneNumber, message);
			LOG.warn(String.format("Trying to send %s to %s via JSON body", message, phoneNumber));
		}
	}

	public void send_json(String phoneNumber, String message) {
		LOG.warn("Building JSON");
        String sendJson = "{"
            .concat(apitokenattribute != "" ? String.format("\"%s\":\"%s\",", apitokenattribute, apitoken): "")
            .concat(String.format("\"%s\":\"%s\",", messageattribute, message))
            .concat(String.format("\"%s\":\"%s\",", receiverattribute, phoneNumber))
            .concat(String.format("\"%s\":\"%s\"", senderattribute, from))
            .concat("}");

        LOG.warn("Creating URI");
        var uri = URI.create(apiurl);
        LOG.warn("Creating body");
        var body = HttpRequest.BodyPublishers.ofString(sendJson);
        LOG.warn("Building Request");
        var request = HttpRequest.newBuilder()
            .uri(uri)
            .header("Content-Type", "application/json")
            .POST(body)
            .build();

        LOG.warn("Starting HTTP client");
        var client = HttpClient.newHttpClient();

        LOG.warn("Retting response");
        HttpResponse<String> response;
		try {
			response = client.send(request, HttpResponse.BodyHandlers.ofString());
			LOG.warn(String.format("Sent message to %s with body %s; Response: %s ", apiurl, sendJson, response));
		} catch (IOException e) {
			LOG.warn(String.format("Failed to send message to %s with body %s", apiurl, sendJson));
			e.printStackTrace();
		} catch (InterruptedException e) {
			LOG.warn(String.format("Failed to send message to %s with body %s", apiurl, sendJson));
			e.printStackTrace();
		}
	}

	public void send_urlencoded(String phoneNumber, String message) {
		Map<String, String> formData = new HashMap<>();
		if (apitokenattribute != "") {
			formData.put(apitokenattribute, apitoken);
		}
		formData.put(messageattribute, message);
		formData.put(receiverattribute, phoneNumber);
		formData.put(senderattribute, from);

	    var client = HttpClient.newHttpClient();
	    var form_data = getFormDataAsString(formData);
	    var request = HttpRequest.newBuilder(URI.create(apiurl))
	            .POST(HttpRequest.BodyPublishers.ofString(form_data))
	            .build();
	    try {
			client.send(request, HttpResponse.BodyHandlers.ofString());
		} catch (IOException e) {
			LOG.warn(String.format("Failed to send message to %s with params %s", apiurl, form_data));
			e.printStackTrace();
		} catch (InterruptedException e) {
			LOG.warn(String.format("Failed to send message to %s with params %s", apiurl, form_data));
			e.printStackTrace();
		}
	}

	private static String getFormDataAsString(Map<String, String> formData) {
	    StringBuilder formBodyBuilder = new StringBuilder();
	    for (Map.Entry<String, String> singleEntry : formData.entrySet()) {
	        if (formBodyBuilder.length() > 0) {
	            formBodyBuilder.append("&");
	        }
	        formBodyBuilder.append(URLEncoder.encode(singleEntry.getKey(), StandardCharsets.UTF_8));
	        formBodyBuilder.append("=");
	        formBodyBuilder.append(URLEncoder.encode(singleEntry.getValue(), StandardCharsets.UTF_8));
	    }
	    return formBodyBuilder.toString();
	}
}
