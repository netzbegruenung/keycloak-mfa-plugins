package netzbegruenung.keycloak.app;

import netzbegruenung.keycloak.app.dto.ChallengeDto;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Stands in for the mobile app: generates its own key pair, registers it against a setup
 * action-token URL and signs challenge responses, mirroring what AppSetupActionTokenHandler /
 * AppAuthActionTokenHandler expect a real device to do. Talks to Keycloak over plain HTTP
 * instead of Selenium, since the setup/auth handshake here is REST-only - the only thing
 * rendered to a browser is the QR code / status page, not the device's side of the exchange.
 */
final class AppDeviceSimulator {

	private static final String KEY_ALGORITHM = "RSA";
	private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

	private final HttpClient httpClient = HttpClient.newHttpClient();
	private final KeyPair keyPair;
	private final String deviceId;

	AppDeviceSimulator() throws NoSuchAlgorithmException {
		this.keyPair = KeyPairGenerator.getInstance(KEY_ALGORITHM).generateKeyPair();
		this.deviceId = UUID.randomUUID().toString();
	}

	String deviceId() {
		return deviceId;
	}

	int register(String actionTokenUrl) throws IOException, InterruptedException {
		String encodedPublicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
		String separator = actionTokenUrl.contains("?") ? "&" : "?";
		String uri = actionTokenUrl + separator
			+ "device_id=" + encode(deviceId)
			+ "&device_os=" + encode("test-os")
			+ "&public_key=" + encode(encodedPublicKey)
			+ "&key_algorithm=" + encode(KEY_ALGORITHM)
			+ "&signature_algorithm=" + encode(SIGNATURE_ALGORITHM)
			+ "&device_push_id=" + encode("test-push-id");

		return send(HttpRequest.newBuilder(URI.create(uri)).GET()).statusCode();
	}

	List<ChallengeDto> fetchChallenges(String challengesUrl) throws IOException, InterruptedException {
		HttpResponse<String> response = send(HttpRequest.newBuilder(URI.create(challengesUrl))
			.header(AuthenticationUtil.SIGNATURE_HEADER, identitySignatureHeader())
			.GET());

		if (response.statusCode() != 200) {
			throw new IllegalStateException("Failed to fetch challenges: " + response.statusCode() + " " + response.body());
		}
		try {
			return List.of(JsonSerialization.readValue(response.body(), ChallengeDto[].class));
		} catch (IOException e) {
			throw new IllegalStateException("Failed to parse challenges response: " + response.body(), e);
		}
	}

	int respond(ChallengeDto challenge, boolean granted) throws IOException, InterruptedException {
		String created = String.valueOf(System.currentTimeMillis());

		Map<String, String> signedDataMap = new HashMap<>();
		signedDataMap.put("created", created);
		signedDataMap.put("secret", challenge.codeChallenge());
		signedDataMap.put("granted", String.valueOf(granted));
		String signedData = AuthenticationUtil.getSignatureString(signedDataMap);

		String signatureHeader = "signature:" + sign(signedData)
			+ ",keyId:" + deviceId
			+ ",created:" + created
			+ ",granted:" + granted;

		return send(HttpRequest.newBuilder(URI.create(challenge.targetUrl()))
			.header(AuthenticationUtil.SIGNATURE_HEADER, signatureHeader)
			.GET()).statusCode();
	}

	private String identitySignatureHeader() {
		String created = String.valueOf(System.currentTimeMillis());
		Map<String, String> signedDataMap = new HashMap<>();
		signedDataMap.put("created", created);
		String signedData = AuthenticationUtil.getSignatureString(signedDataMap);

		return "signature:" + sign(signedData) + ",keyId:" + deviceId + ",created:" + created;
	}

	private String sign(String data) {
		try {
			Signature signer = Signature.getInstance(SIGNATURE_ALGORITHM);
			signer.initSign(keyPair.getPrivate());
			signer.update(data.getBytes(StandardCharsets.UTF_8));
			return Base64.getEncoder().encodeToString(signer.sign());
		} catch (Exception e) {
			throw new IllegalStateException("Failed to sign challenge data", e);
		}
	}

	private HttpResponse<String> send(HttpRequest.Builder request) throws IOException, InterruptedException {
		return httpClient.send(request.build(), HttpResponse.BodyHandlers.ofString());
	}

	private static String encode(String value) {
		return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8);
	}
}
