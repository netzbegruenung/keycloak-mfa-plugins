package netzbegruenung.keycloak.app.jpa;

import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import org.keycloak.models.jpa.entities.RealmEntity;
import org.keycloak.models.jpa.entities.UserEntity;

import jakarta.persistence.*;

@Entity
@Table(name = "APP_AUTH_CREDENTIAL_INDEX", indexes = {
	@Index(name = "idx_app_auth_cred_idx_realm_device", columnList = "realm_id, device_id")
}, uniqueConstraints = {
	@UniqueConstraint(name = "uc_app_auth_cred_idx_realm_device", columnNames = {"realm_id", "device_id"})
})
@NamedQueries({
	@NamedQuery(name = "AppAuthCredentialIndex.findByRealmAndDeviceId", query = "select i from AppAuthCredentialIndex i where i.realm = :realm and i.deviceId = :deviceId")
})
public class AppAuthCredentialIndex {

	// LAZY: only ever dereferenced via .getId(), which resolves from the FK column alone -
	// EAGER (the JPA default for @ManyToOne) would load the full row for no benefit.
	@ManyToOne(optional = false, fetch = FetchType.LAZY)
	@JoinColumn(name = "realm_id", nullable = false)
	@OnDelete(action = OnDeleteAction.CASCADE)
	private RealmEntity realm;

	@ManyToOne(optional = false, fetch = FetchType.LAZY)
	@JoinColumn(name = "user_id", nullable = false)
	@OnDelete(action = OnDeleteAction.CASCADE)
	private UserEntity user;

	@Column(name = "device_id", nullable = false)
	private String deviceId;

	// Assigned identifier (not @GeneratedValue): the caller already has a unique credentialId
	// on hand before persisting, and every consumer already keys off it - a separate
	// generated surrogate id would just be a column nothing ever reads.
	@Id
	@Column(name = "credential_id", nullable = false, length = 36)
	private String credentialId;

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

	public String getDeviceId() {
		return deviceId;
	}

	public void setDeviceId(String deviceId) {
		this.deviceId = deviceId;
	}

	public String getCredentialId() {
		return credentialId;
	}

	public void setCredentialId(String credentialId) {
		this.credentialId = credentialId;
	}
}
