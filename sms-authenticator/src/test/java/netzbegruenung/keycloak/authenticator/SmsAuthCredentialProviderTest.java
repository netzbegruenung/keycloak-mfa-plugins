package netzbegruenung.keycloak.authenticator;

import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialModel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.mockito.ArgumentCaptor;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SmsAuthCredentialProviderTest {

	private SmsAuthCredentialProvider provider;
	private RealmModel realm;
	private UserModel user;
	private SubjectCredentialManager credentials;
	private SmsAuthCredentialModel stored;

	@BeforeEach
	void setUp() {
		provider = new SmsAuthCredentialProvider(mock(KeycloakSession.class));
		realm = mock(RealmModel.class);
		user = mock(UserModel.class);
		credentials = mock(SubjectCredentialManager.class);
		when(user.credentialManager()).thenReturn(credentials);
		stored = SmsAuthCredentialModel.createSmsAuthenticator("+491234567");
		stored.setId("cred-1");
		when(credentials.getStoredCredentialById("cred-1")).thenReturn(stored);
	}

	@Test
	@DisplayName("isValid rejects an input that is not a UserCredentialModel")
	void isValidRejectsOtherInputKinds() {
		assertFalse(provider.isValid(realm, user, mock(CredentialInput.class)));
	}

	@Test
	@DisplayName("isValid rejects an input of another credential type")
	void isValidRejectsOtherTypes() {
		assertFalse(provider.isValid(realm, user, new UserCredentialModel("cred-1", "password", "+491234567")));
	}

	@Test
	@DisplayName("isValid rejects an input without challenge response")
	void isValidRejectsMissingResponse() {
		assertFalse(provider.isValid(realm, user, new UserCredentialModel("cred-1", SmsAuthCredentialModel.TYPE, null)));
	}

	@Test
	@DisplayName("isValid compares the response with the stored number")
	void isValidComparesWithTheStoredNumber() {
		assertTrue(provider.isValid(realm, user,
			new UserCredentialModel("cred-1", SmsAuthCredentialModel.TYPE, "+491234567")));
		assertFalse(provider.isValid(realm, user,
			new UserCredentialModel("cred-1", SmsAuthCredentialModel.TYPE, "+499999999")));
	}

	@Test
	@DisplayName("isConfiguredFor is false for another credential type, without looking at the user")
	void isConfiguredForIgnoresOtherTypes() {
		assertFalse(provider.isConfiguredFor(realm, user, "password"));
		verify(user, never()).credentialManager();
	}

	@Test
	@DisplayName("updateCredential without a stored credential changes nothing")
	void updateWithoutStoredCredentialChangesNothing() {
		when(credentials.getStoredCredentialsByTypeStream(SmsAuthCredentialModel.TYPE)).thenReturn(Stream.empty());

		assertFalse(provider.updateCredential(realm, user,
			new UserCredentialModel("random_id", SmsAuthCredentialModel.TYPE, "+499876543")));
		verify(credentials, never()).createStoredCredential(any());
	}

	@Test
	@DisplayName("updateCredential replaces the stored credential with the new number")
	void updateReplacesTheStoredCredential() {
		when(credentials.getStoredCredentialsByTypeStream(SmsAuthCredentialModel.TYPE)).thenReturn(Stream.of(stored));

		assertTrue(provider.updateCredential(realm, user,
			new UserCredentialModel("random_id", SmsAuthCredentialModel.TYPE, "+499876543")));

		verify(credentials).removeStoredCredentialById("cred-1");
		ArgumentCaptor<CredentialModel> created = ArgumentCaptor.forClass(CredentialModel.class);
		verify(credentials).createStoredCredential(created.capture());
		assertEquals("+499876543",
			SmsAuthCredentialModel.createFromModel(created.getValue()).getSmsAuthenticatorData().getMobileNumber());
	}
}
