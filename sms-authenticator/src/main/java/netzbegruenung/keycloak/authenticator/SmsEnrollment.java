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

package netzbegruenung.keycloak.authenticator;

import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * Shared auto-enrollment logic: creates the mobile-number SMS credential from
 * the user attribute configured in the "sms-2fa" authenticator config. Used by
 * the required-action trigger (login time) and by the admin enrollment REST
 * endpoint (pre-provisioning without a login).
 */
public class SmsEnrollment {

	/**
	 * Create the mobile-number credential for the user from the configured
	 * attribute, if the user has no credential of that type yet.
	 *
	 * @return the enrolled mobile number, or null if the user was not enrolled
	 *         (credential already exists, or no usable attribute value)
	 */
	public static String enrollFromAttribute(KeycloakSession session, RealmModel realm, UserModel user,
		AuthenticatorConfigModel config) {
		if (config == null || config.getConfig() == null) {
			return null;
		}
		if (user.credentialManager()
			.getStoredCredentialsByTypeStream(SmsAuthCredentialModel.TYPE).findAny().isPresent()) {
			return null;
		}
		String mobileNumberAttribute = config.getConfig().getOrDefault("mobileNumberAttribute", "mobile_number");
		String mobileNumber = user.getAttributeStream(mobileNumberAttribute)
			.filter(n -> n != null && !n.isBlank()).findFirst().orElse(null);
		if (mobileNumber == null) {
			return null;
		}
		SmsAuthCredentialProvider credentialProvider = (SmsAuthCredentialProvider) session
			.getProvider(CredentialProvider.class, SmsAuthCredentialProviderFactory.PROVIDER_ID);
		credentialProvider.createCredential(realm, user, SmsAuthCredentialModel.createSmsAuthenticator(mobileNumber));
		return mobileNumber;
	}
}
