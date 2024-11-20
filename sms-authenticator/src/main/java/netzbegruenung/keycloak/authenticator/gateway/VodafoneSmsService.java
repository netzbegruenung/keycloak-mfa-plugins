package netzbegruenung.keycloak.authenticator.gateway;

import org.jboss.logging.Logger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import javax.xml.bind.DatatypeConverter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class VodafoneSmsService implements SmsService {

	private static final Logger logger = Logger.getLogger(VodafoneSmsService.class);

	private final String apiUrl;
	private final String accountId;
	private final String password;
	private final String secureHashKey;

	public VodafoneSmsService(Map<String, String> config) {
		this.apiUrl = config.get("vodafone.api.url");
		this.accountId = config.get("vodafone.account.id");
		this.password = config.get("vodafone.password");
		this.secureHashKey = config.get("vodafone.secure.hash.key");
	}

	@Override
	public void send(String phoneNumber, String message) {
		try {
			String secureHash = generateSecureHash(phoneNumber, message);

			String xmlRequest = generateXmlRequest(phoneNumber, message, secureHash);

			HttpRequest request = HttpRequest.newBuilder()
				.uri(URI.create(apiUrl))
				.header("Content-Type", "application/xml")
				.POST(HttpRequest.BodyPublishers.ofString(xmlRequest))
				.build();

			HttpClient client = HttpClient.newHttpClient();
			HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

			if (response.statusCode() == 200) {
				logger.infof("SMS sent successfully to %s: %s", phoneNumber, response.body());
			} else {
				logger.errorf("Failed to send SMS to %s: %s", phoneNumber, response.body());
			}
		} catch (Exception e) {
			logger.errorf(e, "Error sending SMS to %s", phoneNumber);
		}
	}

	private String generateSecureHash(String phoneNumber, String message) throws Exception {
		String data = String.format("AccountId=%s&Password=%s&SenderName=%s&ReceiverMSISDN=%s&SMSText=%s",
			accountId, password, "TestSender", phoneNumber, message);

		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(new SecretKeySpec(DatatypeConverter.parseHexBinary(secureHashKey), "HmacSHA256"));
		byte[] hashBytes = mac.doFinal(data.getBytes("UTF-8"));

		return DatatypeConverter.printHexBinary(hashBytes);
	}

	private String generateXmlRequest(String phoneNumber, String message, String secureHash) {
		return String.format(
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
				"<SubmitSMSRequest xmlns:=\"http://www.edafa.com/web2sms/sms/model/\"\n" +
				"xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n" +
				"xsi:schemaLocation=\"http://www.edafa.com/web2sms/sms/model/ SMSAPI.xsd \" xsi:type=\"SubmitSMSRequest\">\n" +
				"  <AccountId>%s</AccountId>\n" +
				"  <Password>%s</Password>\n" +
				"  <SecureHash>%s</SecureHash>\n" +
				"  <SMSList>\n" +
				"    <SenderName>%s</SenderName>\n" +
				"    <ReceiverMSISDN>%s</ReceiverMSISDN>\n" +
				"    <SMSText>%s</SMSText>\n" +
				"  </SMSList>\n" +
				"</SubmitSMSRequest>",
			accountId, password, secureHash, "TestSender", phoneNumber, message);
	}
}
