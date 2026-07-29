package netzbegruenung.keycloak.trusteddevice;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.CredentialValidator;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class TrustedDeviceAuthenticator implements Authenticator, CredentialValidator<TrustedDeviceCredentialProvider> {

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        if (getCredentialProvider(context.getSession()).isTrustedDevice(context.getSession(), context.getRealm(), context.getUser())) {
            context.success();
        } else {
            context.getAuthenticationSession().addRequiredAction(TrustedDeviceRegisterRequiredAction.PROVIDER_ID);
            context.attempted();
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return user.credentialManager().isConfiguredFor(getCredentialProvider(session).getType());
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }

    @Override
    public TrustedDeviceCredentialProvider getCredentialProvider(KeycloakSession session) {
        return (TrustedDeviceCredentialProvider) session.getProvider(CredentialProvider.class, TrustedDeviceCredentialProviderFactory.PROVIDER_ID);
    }
}
