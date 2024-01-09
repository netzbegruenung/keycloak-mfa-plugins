package netzbegruenung.keycloak.app.jpa;

import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.keycloak.models.jpa.entities.RealmEntity;
import org.keycloak.models.jpa.entities.UserEntity;

import jakarta.persistence.*;
import java.util.UUID;

@Entity
@Table(name = "APP_AUTH_CHALLENGE", indexes = {
	@Index(name = "idx_challenge_realm_id", columnList = "realm_id, device_id")
}, uniqueConstraints = {
	@UniqueConstraint(name = "uc_challenge_realm_id", columnNames = {"realm_id", "device_id"})
})
@NamedQueries({
	@NamedQuery(name = "Challenge.findByRealmAndDeviceId", query = "select c from Challenge c where c.realm = :realm and c.deviceId = :deviceId"),
	@NamedQuery(name = "Challenge.deleteByRealmAndDeviceId", query = "delete from Challenge c where c.realm = :realm and c.deviceId = :deviceId")
})
public class Challenge {

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	@Column(name = "id", nullable = false)
	private UUID id;

	@ManyToOne(optional = false)
	@JoinColumn(name = "realm_id", nullable = false)
	@OnDelete(action = OnDeleteAction.CASCADE)
	private RealmEntity realm;

	@ManyToOne(optional = false)
	@JoinColumn(name = "user_id", nullable = false)
	@OnDelete(action = OnDeleteAction.CASCADE)
	private UserEntity user;

	@ManyToOne(optional = false)
	@JoinColumn(name = "client_id", nullable = false)
	@OnDelete(action = OnDeleteAction.CASCADE)
	private ClientEntity client;

	@Column(name = "target_url", nullable = false, length = 1023)
	private String targetUrl;

	@Column(name = "device_id", nullable = false)
	private String deviceId;

	@Column(name = "secret", nullable = false, length = 1023)
	private String secret;

	@Column(name = "updated_timestamp", nullable = false)
	private Long updatedTimestamp;

	@Column(name = "ip_address", length = 63)
	private String ipAddress;

	@Column(name = "device", length = 63)
	private String device;

	@Column(name = "browser", length = 63)
	private String browser;

	@Column(name = "os", length = 63)
	private String os;

	@Column(name = "os_version", length = 63)
	private String osVersion;

	@Column(name = "expires_at", nullable = false)
	private Long expiresAt;

	public UUID getId() {
		return id;
	}

	public RealmEntity getRealm() {
		return realm;
	}

	public void setRealm(RealmEntity realm) {
		this.realm = realm;
	}

	public UserEntity getUser() {
		return user;
	}

	public void setUser(UserEntity user) {
		this.user = user;
	}

	public String getTargetUrl() {
		return targetUrl;
	}

	public void setTargetUrl(String targetUrl) {
		this.targetUrl = targetUrl;
	}

	public String getDeviceId() {
		return deviceId;
	}

	public void setDeviceId(String deviceId) {
		this.deviceId = deviceId;
	}

	public String getSecret() {
		return secret;
	}

	public void setSecret(String secret) {
		this.secret = secret;
	}

	public Long getUpdatedTimestamp() {
		return updatedTimestamp;
	}

	public void setUpdatedTimestamp(Long updatedTimestamp) {
		this.updatedTimestamp = updatedTimestamp;
	}

	public String getIpAddress() {
		return ipAddress;
	}

	public void setIpAddress(String ipAddress) {
		this.ipAddress = ipAddress;
	}

	public String getDevice() {
		return device;
	}

	public void setDevice(String device) {
		this.device = device;
	}

	public String getBrowser() {
		return browser;
	}

	public void setBrowser(String browser) {
		this.browser = browser;
	}

	public String getOs() {
		return os;
	}

	public void setOs(String os) {
		this.os = os;
	}

	public String getOsVersion() {
		return osVersion;
	}

	public void setOsVersion(String osVersion) {
		this.osVersion = osVersion;
	}

	public ClientEntity getClient() {
		return client;
	}

	public void setClient(ClientEntity client) {
		this.client = client;
	}

	public Long getExpiresAt() {
		return expiresAt;
	}

	public void setExpiresAt(Long expiresAt) {
		this.expiresAt = expiresAt;
	}
}
