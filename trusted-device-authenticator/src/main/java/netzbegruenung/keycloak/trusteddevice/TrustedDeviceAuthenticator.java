package netzbegruenung.keycloak.trusteddevice;

import netzbegruenung.keycloak.trusteddevice.credentials.TrustedDeviceCredentialModel;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.CredentialValidator;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class TrustedDeviceAuthenticator implements Authenticator, CredentialValidator<TrustedDeviceCredentialProvider> {

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        TrustedDeviceCredentialModel credential = validateCookie(context.getSession(), context.getUser());
        if (credential != null) {
            context.success();
        } else {
            context.getAuthenticationSession().addRequiredAction(TrustedDeviceRegisterRequiredAction.PROVIDER_ID);
            context.attempted();
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
    }

    public TrustedDeviceCredentialModel validateCookie(KeycloakSession session, UserModel user) {
        TrustedDeviceToken deviceToken = getToken(session);
        if (deviceToken == null) {
            return null;
        }

        return user.credentialManager().getStoredCredentialsByTypeStream(TrustedDeviceCredentialModel.TYPE)
                .map(TrustedDeviceCredentialModel::createFromCredentialModel)
                .filter(c -> c.getDeviceId().equals(deviceToken.getDeviceId()))
                .filter(c -> c.getExpireTime() > Time.currentTime())
                .findFirst()
                .orElse(null);
    }

    public TrustedDeviceToken getToken(KeycloakSession session) {
        String tokenString = TrustedDeviceCookie.read(session);
        if (tokenString == null) {
            return null;
        }

        TrustedDeviceToken decoded = session.tokens().decode(tokenString, TrustedDeviceToken.class);
        if (decoded != null && decoded.getExp() > Time.currentTime()) {
            return decoded;
        }

        return null;
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
