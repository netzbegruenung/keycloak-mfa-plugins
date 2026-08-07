package netzbegruenung.keycloak.trusteddevice;

import netzbegruenung.keycloak.trusteddevice.credentials.TrustedDeviceCredentialModel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.events.Details;
import org.keycloak.events.EventType;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.testframework.annotations.InjectEvents;
import org.keycloak.testframework.annotations.InjectKeycloakUrls;
import org.keycloak.testframework.annotations.InjectRealm;
import org.keycloak.testframework.annotations.InjectUser;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.annotations.TestSetup;
import org.keycloak.testframework.injection.LifeCycle;
import org.keycloak.testframework.events.EventAssertion;
import org.keycloak.testframework.events.Events;
import org.keycloak.testframework.oauth.OAuthClient;
import org.keycloak.testframework.oauth.annotations.InjectOAuthClient;
import org.keycloak.testframework.realm.ManagedRealm;
import org.keycloak.testframework.realm.ManagedUser;
import org.keycloak.testframework.realm.UserConfig;
import org.keycloak.testframework.realm.UserBuilder;
import org.keycloak.testframework.remote.runonserver.InjectRunOnServer;
import org.keycloak.testframework.remote.runonserver.RunOnServerClient;
import org.keycloak.testframework.server.KeycloakServerConfig;
import org.keycloak.testframework.server.KeycloakServerConfigBuilder;
import org.keycloak.testframework.server.KeycloakUrls;
import org.keycloak.testframework.ui.annotations.InjectPage;
import org.keycloak.testframework.ui.annotations.InjectWebDriver;
import org.keycloak.testframework.ui.page.LoginPage;
import org.keycloak.testframework.ui.webdriver.ManagedWebDriver;
import org.keycloak.testsuite.util.FlowUtil;
import org.openqa.selenium.Cookie;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

@KeycloakIntegrationTest(config = TrustedDeviceLoginFlowTest.ServerConfig.class)
public class TrustedDeviceLoginFlowTest {

    @InjectRealm
    ManagedRealm managedRealm;

    @InjectUser(config = LoginFlowUserConfig.class, lifecycle = LifeCycle.METHOD)
    ManagedUser user;

    @InjectRunOnServer(permittedPackages = "netzbegruenung.keycloak.trusteddevice")
    RunOnServerClient runOnServer;

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
    public void setUpFlow() {
        TrustedDeviceTestSupport.registerRequiredAction(managedRealm, TrustedDeviceRegisterRequiredAction.PROVIDER_ID);

        runOnServer.run(session -> FlowUtil.inCurrentRealm(session).copyBrowserFlow("browser-trusted-device-flow"));
        runOnServer.run(session -> FlowUtil.inCurrentRealm(session)
                .selectFlow("browser-trusted-device-flow")
                .inForms(forms -> forms
                        .clear()
                        .addSubFlowExecution(AuthenticationExecutionModel.Requirement.REQUIRED, subflow -> subflow
                                .addAuthenticatorExecution(AuthenticationExecutionModel.Requirement.REQUIRED, "auth-username-password-form")
                                .addSubFlowExecution(AuthenticationExecutionModel.Requirement.REQUIRED, trustedOrRegister -> trustedOrRegister
                                        .addAuthenticatorExecution(AuthenticationExecutionModel.Requirement.ALTERNATIVE, TrustedDeviceAuthenticatorFactory.PROVIDER_ID)
                                        .addAuthenticatorExecution(AuthenticationExecutionModel.Requirement.ALTERNATIVE, TrustedDeviceRegisterAuthenticatorFactory.PROVIDER_ID)
                                )
                        )
                )
                .defineAsBrowserFlow());
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
    public void firstLoginRegistersDevice() {
        loginAndTrustDevice();
    }

    @Test
    public void secondLoginWithCookieBypassesRegister() {
        loginAndTrustDevice();
        logout();
        events.clear();

        oauth.openLoginForm();
        loginPage.fillLogin(user.getUsername(), user.getPassword());
        loginPage.submit();

        EventAssertion.assertSuccess(events.poll())
                .type(EventType.LOGIN)
                .userId(user.getId())
                .details(Details.USERNAME, user.getUsername());
    }

    @Test
    public void decliningNeverSetsCookie() {
        loginAndDeclineDevice();
        logout();
        events.clear();

        loginAndDeclineDevice();
    }

    private void loginAndTrustDevice() {
        oauth.openLoginForm();
        loginPage.assertCurrent();
        loginPage.fillLogin(user.getUsername(), user.getPassword());
        loginPage.submit();

        trustDevicePage.assertCurrent();
        trustDevicePage.confirmDevice();

        EventAssertion.assertSuccess(events.poll())
                .type(EventType.UPDATE_CREDENTIAL)
                .userId(user.getId())
                .details(Details.CREDENTIAL_TYPE, TrustedDeviceCredentialModel.TYPE);

        driver.open(keycloakUrls.getBase() + "/realms/" + managedRealm.getName() + "/account");
        Cookie cookie = driver.cookies().get(TrustedDeviceCookie.NAME);
        assertThat("TRUSTED_DEVICE cookie should be set after confirming", cookie, notNullValue());
    }

    private void loginAndDeclineDevice() {
        oauth.openLoginForm();
        loginPage.assertCurrent();
        loginPage.fillLogin(user.getUsername(), user.getPassword());
        loginPage.submit();

        trustDevicePage.assertCurrent();
        trustDevicePage.rejectDevice();

        EventAssertion.assertError(events.poll())
                .type(EventType.UPDATE_CREDENTIAL_ERROR)
                .userId(user.getId())
                .details(Details.CREDENTIAL_TYPE, TrustedDeviceCredentialModel.TYPE)
                .details(Details.REASON, "user_declined");

        driver.open(keycloakUrls.getBase() + "/realms/" + managedRealm.getName() + "/account");
        Cookie cookie = driver.cookies().get(TrustedDeviceCookie.NAME);
        assertThat("TRUSTED_DEVICE cookie should not be set after declining", cookie, nullValue());
    }

    private void logout() {
        managedRealm.admin().users().get(user.getId()).logout();
    }

    public static class LoginFlowUserConfig implements UserConfig {
        @Override
        public UserBuilder configure(UserBuilder user) {
            return user.username("login-flow-user")
                    .password("password")
                    .name("Login", "Flow")
                    .email("login-flow@example.com")
                    .emailVerified(true);
        }
    }

    public static class ServerConfig implements KeycloakServerConfig {
        @Override
        public KeycloakServerConfigBuilder configure(KeycloakServerConfigBuilder config) {
            return config.dependencyCurrentProject()
                    .dependency("org.keycloak.tests", "keycloak-tests-utils-shared");
        }
    }
}
