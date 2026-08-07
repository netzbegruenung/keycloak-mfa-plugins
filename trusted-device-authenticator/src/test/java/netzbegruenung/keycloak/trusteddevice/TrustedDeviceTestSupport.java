package netzbegruenung.keycloak.trusteddevice;

import org.keycloak.testframework.realm.ManagedRealm;

/**
 * Custom required actions aren't auto-registered for a realm (only Keycloak's built-in
 * DefaultRequiredActions are) - an admin normally does this once via "Authentication ->
 * Required Actions -> register". Tests need the same one-time registration step.
 */
final class TrustedDeviceTestSupport {

    private TrustedDeviceTestSupport() {
    }

    static void registerRequiredAction(ManagedRealm realm, String providerId) {
        realm.admin().flows().getUnregisteredRequiredActions().stream()
                .filter(action -> providerId.equals(action.getProviderId()))
                .findFirst()
                .ifPresent(action -> realm.admin().flows().registerRequiredAction(action));
    }
}
