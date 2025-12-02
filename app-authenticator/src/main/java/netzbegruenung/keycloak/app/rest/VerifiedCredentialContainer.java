package netzbegruenung.keycloak.app.rest;

import org.keycloak.models.UserModel;
import org.keycloak.credential.CredentialModel;
import netzbegruenung.keycloak.app.credentials.AppCredentialModel;

public record VerifiedCredentialContainer(UserModel user, CredentialModel credential, AppCredentialModel appCredential) {}
