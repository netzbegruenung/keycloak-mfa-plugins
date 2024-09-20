package netzbegruenung.keycloak.app;

import com.google.common.base.Joiner;
import com.google.common.base.Splitter;
import netzbegruenung.keycloak.app.credentials.AppCredentialData;
import org.apache.commons.codec.binary.Base64;
import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.models.UserModel;

import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import java.util.Map;

public class AuthenticationUtil {

	private static final Logger logger = Logger.getLogger(AuthenticationUtil.class);
	private static final Splitter.MapSplitter signatureMapSplitter = Splitter.on(",").withKeyValueSeparator(":");

	public static Map<String, String> getSignatureMap(List<String> signatureHeaders) {
		if (signatureHeaders.isEmpty()) {
			return null;
		}

		String signatureHeader = signatureHeaders.get(0);
		Map<String, String> signatureMap = signatureMapSplitter.split(signatureHeader);

		if (
			!signatureMap.containsKey("signature")
			|| !signatureMap.containsKey("keyId")
			|| !signatureMap.containsKey("created")
		) {
			logger.warnf("Failed to parse signature header: header must at least contain keys: signature, keyId, created");
			return null;
		}

		try {
			if (Long.parseLong(signatureMap.get("created")) > Time.currentTimeMillis() + 1000 * 10) {
				logger.warnf("Failed to parse signature header: created is in the future device ID [%s]", signatureMap.get("keyId"));
				return null;
			}
		} catch (NumberFormatException e) {
			logger.warnf(e, "Failed to parse signature header: created is not a parsable long device ID [%s]", signatureMap.get("keyId"));
			return null;
		}

		return signatureMap;
	}

	public static String getSignatureString(Map<String, String> signedData) {
		return Joiner.on(",").withKeyValueSeparator(":").join(signedData);
	}

	public static boolean verifyChallenge(UserModel user, AppCredentialData appCredentialData, String signedData, String signature) {
		try {
			KeyFactory keyFactory = KeyFactory.getInstance(appCredentialData.getKeyAlgorithm());
			byte[] publicKeyBytes = Base64.decodeBase64(appCredentialData.getPublicKey());
			EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
			PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

			Signature sign = Signature.getInstance(appCredentialData.getSignatureAlgorithm());
			sign.initVerify(publicKey);
			sign.update(signedData.getBytes());

			if (!sign.verify(Base64.decodeBase64(signature))) {
				logger.warnv("App authentication rejected: invalid signature for user [{0}]", user.getUsername());
				return false;
			}
			return true;
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | SignatureException | InvalidKeyException e) {
			logger.warnf(
				e,
				"App authentication rejected: signature verification failed for user: [%s], probably due to malformed signature or wrong algorithm",
				user.getUsername()
			);
			return false;
		}
	}

}
