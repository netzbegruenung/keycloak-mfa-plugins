package netzbegruenung.keycloak.trusteddevice;

import netzbegruenung.keycloak.trusteddevice.credentials.TrustedDeviceCredentialModel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.testframework.annotations.TestSetup;
import org.keycloak.events.Details;
import org.keycloak.events.EventType;
import org.keycloak.representations.idm.EventRepresentation;
import org.keycloak.testframework.annotations.InjectEvents;
import org.keycloak.testframework.annotations.InjectKeycloakUrls;
import org.keycloak.testframework.annotations.InjectRealm;
import org.keycloak.testframework.annotations.InjectUser;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.injection.LifeCycle;
import org.keycloak.testframework.events.EventAssertion;
import org.keycloak.testframework.events.Events;
import org.keycloak.testframework.oauth.OAuthClient;
import org.keycloak.testframework.oauth.annotations.InjectOAuthClient;
import org.keycloak.testframework.realm.ManagedRealm;
import org.keycloak.testframework.realm.ManagedUser;
import org.keycloak.testframework.realm.UserConfig;
import org.keycloak.testframework.realm.UserConfigBuilder;
import org.keycloak.testframework.server.KeycloakServerConfig;
import org.keycloak.testframework.server.KeycloakServerConfigBuilder;
import org.keycloak.testframework.server.KeycloakUrls;
import org.keycloak.testframework.ui.annotations.InjectPage;
import org.keycloak.testframework.ui.annotations.InjectWebDriver;
import org.keycloak.testframework.ui.page.LoginPage;
import org.keycloak.testframework.ui.webdriver.ManagedWebDriver;
import org.openqa.selenium.Cookie;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

@KeycloakIntegrationTest(config = TrustedDeviceRegisterRequiredActionTest.ServerConfig.class)
public class TrustedDeviceRegisterRequiredActionTest {

    @InjectRealm
    ManagedRealm managedRealm;

    @InjectUser(config = RequiredActionUserConfig.class, lifecycle = LifeCycle.METHOD)
    ManagedUser user;

    @InjectWebDriver
    ManagedWebDriver driver;

    @InjectOAuthClient
    OAuthClient oauth;

    @InjectEvents
    Events events;

    @InjectPage
    LoginPage loginPage;

    @InjectPage
    TrustedDeviceRegisterPage trustDevicePage;

    @InjectKeycloakUrls
    KeycloakUrls keycloakUrls;

    @TestSetup
    public void registerRequiredAction() {
        TrustedDeviceTestSupport.registerRequiredAction(managedRealm, TrustedDeviceRegisterRequiredAction.PROVIDER_ID);
    }

    @BeforeEach
    public void clearBrowserState() {
        // navigate to the Keycloak origin first - deleteAllCookies() only clears cookies visible
        // from the browser's current domain, which may still be a leftover page from a prior test.
        driver.open(keycloakUrls.getBase());
        driver.cookies().deleteAll();
        events.clear();
    }

    @Test
    public void declineTrustedDevice() {
        oauth.openLoginForm();
        loginPage.fillLogin(user.getUsername(), user.getPassword());
        loginPage.submit();

        trustDevicePage.assertCurrent();
        trustDevicePage.rejectDevice();

        EventRepresentation credentialEvent = events.poll();
        EventAssertion.assertError(credentialEvent)
                .type(EventType.UPDATE_CREDENTIAL_ERROR)
                .userId(user.getId())
                .details(Details.CREDENTIAL_TYPE, TrustedDeviceCredentialModel.TYPE)
                .details(Details.REASON, "user_declined");

        driver.open(keycloakUrls.getBase() + "/realms/" + managedRealm.getName() + "/account");
        Cookie cookie = driver.cookies().get(TrustedDeviceCookie.NAME);
        assertThat("TRUSTED_DEVICE cookie should not be set after declining", cookie, nullValue());
    }

    @Test
    public void confirmTrustedDevice() {
        oauth.openLoginForm();
        loginPage.fillLogin(user.getUsername(), user.getPassword());
        loginPage.submit();

        trustDevicePage.assertCurrent();
        trustDevicePage.confirmDevice();

        EventRepresentation credentialEvent = events.poll();
        EventAssertion.assertSuccess(credentialEvent)
                .type(EventType.UPDATE_CREDENTIAL)
                .userId(user.getId())
                .details(Details.CREDENTIAL_TYPE, TrustedDeviceCredentialModel.TYPE);

        driver.open(keycloakUrls.getBase() + "/realms/" + managedRealm.getName() + "/account");
        Cookie cookie = driver.cookies().get(TrustedDeviceCookie.NAME);
        assertThat("TRUSTED_DEVICE cookie should be set after confirming", cookie, notNullValue());
    }

    public static class RequiredActionUserConfig implements UserConfig {
        @Override
        public UserConfigBuilder configure(UserConfigBuilder user) {
            return user.username("trusted-device-user")
                    .password("password")
                    .name("Trusted", "Device")
                    .email("trusted-device@example.com")
                    .emailVerified(true)
                    .requiredActions(TrustedDeviceRegisterRequiredAction.PROVIDER_ID);
        }
    }

    public static class ServerConfig implements KeycloakServerConfig {
        @Override
        public KeycloakServerConfigBuilder configure(KeycloakServerConfigBuilder config) {
            return config.dependencyCurrentProject();
        }
    }
}
