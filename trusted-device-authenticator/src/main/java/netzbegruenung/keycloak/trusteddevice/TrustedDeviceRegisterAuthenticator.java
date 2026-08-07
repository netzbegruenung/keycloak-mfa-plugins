package netzbegruenung.keycloak.trusteddevice;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class TrustedDeviceRegisterAuthenticator implements Authenticator {

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        TrustedDeviceCredentialProvider provider = (TrustedDeviceCredentialProvider)
                context.getSession().getProvider(CredentialProvider.class, TrustedDeviceCredentialProviderFactory.PROVIDER_ID);
        if (provider.isTrustedDevice(context.getSession(), context.getRealm(), context.getUser())) {
            context.success();
            return;
        }

        context.getUser().addRequiredAction(TrustedDeviceRegisterRequiredAction.PROVIDER_ID);
        context.success();
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
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        user.addRequiredAction(TrustedDeviceRegisterRequiredAction.PROVIDER_ID);
    }

    @Override
    public void close() {
    }
}
