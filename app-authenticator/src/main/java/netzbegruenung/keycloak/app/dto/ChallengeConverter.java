package netzbegruenung.keycloak.app.dto;

import netzbegruenung.keycloak.app.jpa.Challenge;
import org.keycloak.common.util.StringPropertyReplacer;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.util.ResolveRelative;
import org.keycloak.theme.Theme;

import java.io.IOException;
import java.util.Locale;
import java.util.Properties;

public class ChallengeConverter {
	public static ChallengeDto getChallengeDto(Challenge challenge, KeycloakSession session) {
		return new ChallengeDto(
			challenge.getUser().getUsername(),
			challenge.getUser().getFirstName(),
			challenge.getUser().getLastName(),
			challenge.getTargetUrl(),
			challenge.getSecret(),
			challenge.getUpdatedTimestamp(),
			challenge.getIpAddress(),
			challenge.getDevice(),
			challenge.getBrowser(),
			challenge.getOs(),
			challenge.getOsVersion(),
			resolveClientName(challenge.getClient().getName(), session),
			ResolveRelative.resolveRelativeUri(session, challenge.getClient().getRootUrl(), challenge.getClient().getBaseUrl())
		);
	}

	private static String resolveClientName(String clientName, KeycloakSession session) {
		return StringPropertyReplacer.replaceProperties(clientName, getProperties(session));
	}

	private static Properties getProperties(KeycloakSession session) {
		try {
			return session.theme().getTheme(Theme.Type.ACCOUNT).getMessages(Locale.ENGLISH);
		} catch (IOException e) {
			return null;
		}
	}
}
