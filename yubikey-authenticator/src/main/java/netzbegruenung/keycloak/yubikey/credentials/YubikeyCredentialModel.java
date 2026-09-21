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

package netzbegruenung.keycloak.yubikey.credentials;

import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;

public class YubikeyCredentialModel extends CredentialModel {
	public static final String TYPE = "yubikey";

	private final YubikeyCredentialData yubikeyData;

	private YubikeyCredentialModel(YubikeyCredentialData yubikeyData) {
		this.yubikeyData = yubikeyData;
	}

	public static YubikeyCredentialModel createFromModel(CredentialModel credentialModel) {
		try {
			YubikeyCredentialData credentialData = JsonSerialization.readValue(credentialModel.getCredentialData(), YubikeyCredentialData.class);

			YubikeyCredentialModel yubikeyCredentialModel = new YubikeyCredentialModel(credentialData);
			yubikeyCredentialModel.setUserLabel(credentialModel.getUserLabel());
			yubikeyCredentialModel.setCreatedDate(credentialModel.getCreatedDate());
			yubikeyCredentialModel.setType(TYPE);
			yubikeyCredentialModel.setId(credentialModel.getId());
			yubikeyCredentialModel.setCredentialData(credentialModel.getCredentialData());
			return yubikeyCredentialModel;
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public static YubikeyCredentialModel createYubikey(String publicId, String label) {
		YubikeyCredentialModel credentialModel = new YubikeyCredentialModel(new YubikeyCredentialData(publicId));
		credentialModel.fillCredentialModelFields(label);
		return credentialModel;
	}

	public YubikeyCredentialData getYubikeyData() {
		return yubikeyData;
	}

	private void fillCredentialModelFields(String label) {
		try {
			setCredentialData(JsonSerialization.writeValueAsString(yubikeyData));
			setType(TYPE);
			setCreatedDate(Time.currentTimeMillis());
			setUserLabel(label);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
}
