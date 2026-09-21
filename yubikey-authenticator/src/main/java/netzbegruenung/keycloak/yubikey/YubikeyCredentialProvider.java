/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author Netzbegruenung e.V.
 * @author verdigado eG
 */

package netzbegruenung.keycloak.yubikey;

import netzbegruenung.keycloak.yubikey.credentials.YubikeyCredentialModel;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputUpdater;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialTypeMetadata;
import org.keycloak.credential.CredentialTypeMetadataContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.stream.Stream;

public class YubikeyCredentialProvider implements CredentialProvider<YubikeyCredentialModel>, CredentialInputValidator, CredentialInputUpdater {

	protected final KeycloakSession session;

	public YubikeyCredentialProvider(KeycloakSession session) {
		this.session = session;
	}

	@Override
	public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
		// Real validation happens against the live Yubico API in the Authenticator,
		// which does not go through this generic credential-input path.
		return false;
	}

	@Override
	public boolean supportsCredentialType(String credentialType) {
		return getType().equals(credentialType);
	}

	@Override
	public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
		if (!supportsCredentialType(credentialType)) return false;
		return user.credentialManager().getStoredCredentialsByTypeStream(credentialType).findAny().isPresent();
	}

	@Override
	public CredentialModel createCredential(RealmModel realm, UserModel user, YubikeyCredentialModel credentialModel) {
		credentialModel.setCreatedDate(Time.currentTimeMillis());
		return user.credentialManager().createStoredCredential(credentialModel);
	}

	@Override
	public boolean updateCredential(RealmModel realm, UserModel user, CredentialInput input) {
		return false;
	}

	@Override
	public boolean deleteCredential(RealmModel realm, UserModel user, String credentialId) {
		return user.credentialManager().removeStoredCredentialById(credentialId);
	}

	@Override
	public YubikeyCredentialModel getCredentialFromModel(CredentialModel model) {
		return YubikeyCredentialModel.createFromModel(model);
	}

	@Override
	public CredentialTypeMetadata getCredentialTypeMetadata(CredentialTypeMetadataContext metadataContext) {
		return CredentialTypeMetadata.builder()
				.type(getType())
				.category(CredentialTypeMetadata.Category.TWO_FACTOR)
				.displayName("yubikey-display-name")
				.helpText("yubikeyHelpText")
				.createAction(YubikeyRequiredAction.PROVIDER_ID)
				.removeable(true)
				.build(session);
	}

	@Override
	public String getType() {
		return YubikeyCredentialModel.TYPE;
	}

	@Override
	public Stream<String> getDisableableCredentialTypesStream(RealmModel realm, UserModel user) {
		return Stream.empty();
	}

	@Override
	public void disableCredentialType(RealmModel realm, UserModel user, String credentialType) {}
}
