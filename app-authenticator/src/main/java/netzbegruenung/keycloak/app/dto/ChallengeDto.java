package netzbegruenung.keycloak.app.dto;

import java.io.Serializable;
import java.util.Objects;

/**
 * A DTO for the {@link netzbegruenung.keycloak.app.jpa.Challenge} entity
 */
public class ChallengeDto implements Serializable {
	private final String userName;
	private final String userFirstName;
	private final String userLastName;
	private final String targetUrl;
	private final String codeChallenge;
	private final Long updatedTimestamp;
	private final String ipAddress;
	private final String device;
	private final String browser;
	private final String os;
	private final String osVersion;
	private final String clientName;
	private final String clientUrl;

	public ChallengeDto(String userName, String userFirstName, String userLastName, String targetUrl, String codeChallenge, Long updatedTimestamp, String ipAddress, String device, String browser, String os, String osVersion, String clientName, String clientUrl) {
		this.userName = userName;
		this.userFirstName = userFirstName;
		this.userLastName = userLastName;
		this.targetUrl = targetUrl;
		this.codeChallenge = codeChallenge;
		this.updatedTimestamp = updatedTimestamp;
		this.ipAddress = ipAddress;
		this.device = device;
		this.browser = browser;
		this.os = os;
		this.osVersion = osVersion;
		this.clientName = clientName;
		this.clientUrl = clientUrl;
	}

	public String getUserName() {
		return userName;
	}

	public String getUserFirstName() {
		return userFirstName;
	}

	public String getUserLastName() {
		return userLastName;
	}

	public String getTargetUrl() {
		return targetUrl;
	}

	public String getCodeChallenge() {
		return codeChallenge;
	}

	public Long getUpdatedTimestamp() {
		return updatedTimestamp;
	}

	public String getIpAddress() {
		return ipAddress;
	}

	public String getDevice() {
		return device;
	}

	public String getBrowser() {
		return browser;
	}

	public String getOs() {
		return os;
	}

	public String getOsVersion() {
		return osVersion;
	}

	public String getClientName() {
		return clientName;
	}

	public String getClientUrl() {
		return clientUrl;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		ChallengeDto entity = (ChallengeDto) o;
		return Objects.equals(this.userName, entity.userName) &&
			Objects.equals(this.userFirstName, entity.userFirstName) &&
			Objects.equals(this.userLastName, entity.userLastName) &&
			Objects.equals(this.targetUrl, entity.targetUrl) &&
			Objects.equals(this.codeChallenge, entity.codeChallenge) &&
			Objects.equals(this.updatedTimestamp, entity.updatedTimestamp) &&
			Objects.equals(this.ipAddress, entity.ipAddress) &&
			Objects.equals(this.device, entity.device) &&
			Objects.equals(this.browser, entity.browser) &&
			Objects.equals(this.os, entity.os) &&
			Objects.equals(this.osVersion, entity.osVersion) &&
			Objects.equals(this.clientName, entity.clientName) &&
			Objects.equals(this.clientUrl, entity.clientUrl);
	}

	@Override
	public int hashCode() {
		return Objects.hash(userName, userFirstName, userLastName, targetUrl, codeChallenge, updatedTimestamp, ipAddress, device, browser, os, osVersion, clientName, clientUrl);
	}
}
