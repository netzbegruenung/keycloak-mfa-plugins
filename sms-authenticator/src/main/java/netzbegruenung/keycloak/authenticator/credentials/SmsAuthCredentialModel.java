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
 * @author <a href="mailto:alistair.doswald@elca.ch">Alistair Doswald</a>
 * @author Netzbegruenung e.V.
 * @author verdigado eG
 */

package netzbegruenung.keycloak.authenticator.credentials;

import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;

public class SmsAuthCredentialModel extends CredentialModel {
	public static final String TYPE = "mobile-number";

	private final SmsAuthCredentialData mobileNumber;


	private SmsAuthCredentialModel(SmsAuthCredentialData mobileNumber) {
		this.mobileNumber = mobileNumber;
	}

	private SmsAuthCredentialModel(String mobileNumberString) {
		mobileNumber = new SmsAuthCredentialData(mobileNumberString);
	}

	public static SmsAuthCredentialModel createFromModel(CredentialModel credentialModel){
		try {
			SmsAuthCredentialData credentialData = JsonSerialization.readValue(credentialModel.getCredentialData(), SmsAuthCredentialData.class);

			SmsAuthCredentialModel smsAuthenticatorModel = new SmsAuthCredentialModel(credentialData);
			smsAuthenticatorModel.setUserLabel(
					"Mobile Number: ***" + credentialData.getMobileNumber().substring(
							Math.max(credentialData.getMobileNumber().length() - 3, 0)
					)
			);
			smsAuthenticatorModel.setCreatedDate(credentialModel.getCreatedDate());
			smsAuthenticatorModel.setType(TYPE);
			smsAuthenticatorModel.setId(credentialModel.getId());
			smsAuthenticatorModel.setCredentialData(credentialModel.getCredentialData());
			return smsAuthenticatorModel;
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}


	public static SmsAuthCredentialModel createSmsAuthenticator(String mobileNumber) {
		SmsAuthCredentialModel credentialModel = new SmsAuthCredentialModel(mobileNumber);
		credentialModel.fillCredentialModelFields();
		return credentialModel;
	}

	public SmsAuthCredentialData getSmsAuthenticatorData() {
		return mobileNumber;
	}

	private void fillCredentialModelFields(){
		try {
			setCredentialData(JsonSerialization.writeValueAsString(mobileNumber));
			setType(TYPE);
			setCreatedDate(Time.currentTimeMillis());
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
}
