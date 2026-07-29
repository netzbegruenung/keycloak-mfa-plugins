package netzbegruenung.keycloak.trusteddevice;

import netzbegruenung.keycloak.trusteddevice.credentials.TrustedDeviceCredentialModel;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class TrustedDeviceRegisterAuthenticator implements Authenticator {

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        String tokenString = TrustedDeviceCookie.read(context.getSession());
        TrustedDeviceToken deviceToken = tokenString == null
                ? null
                : context.getSession().tokens().decode(tokenString, TrustedDeviceToken.class);

        if (deviceToken != null && deviceToken.getExp() > Time.currentTime()) {
            boolean tokenIsValid = context.getUser().credentialManager()
                    .getStoredCredentialsByTypeStream(TrustedDeviceCredentialModel.TYPE)
                    .map(TrustedDeviceCredentialModel::createFromCredentialModel)
                    .anyMatch(c -> c.getDeviceId().equals(deviceToken.getDeviceId()) && c.getExpireTime() > Time.currentTime());
            if (tokenIsValid) {
                context.success();
                return;
            }
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
