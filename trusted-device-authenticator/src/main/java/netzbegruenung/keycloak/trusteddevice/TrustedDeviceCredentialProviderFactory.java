package netzbegruenung.keycloak.trusteddevice;

import netzbegruenung.keycloak.trusteddevice.credentials.TrustedDeviceCredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.models.KeycloakSession;

public class TrustedDeviceCredentialProviderFactory implements CredentialProviderFactory<TrustedDeviceCredentialProvider> {

    public static final String PROVIDER_ID = "nb-trusted-device";

    @Override
    public CredentialProvider<TrustedDeviceCredentialModel> create(KeycloakSession session) {
        return new TrustedDeviceCredentialProvider(session);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
