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
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @author Netzbegruenung e.V.
 * @author verdigado eG
 */

package netzbegruenung.keycloak.authenticator;

import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RequiredActionConfigModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;
import java.util.Map;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class PhoneNumberRequiredActionFactory implements RequiredActionFactory {

    private static final PhoneNumberRequiredAction SINGLETON = new PhoneNumberRequiredAction();

    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public String getId() {
        return PhoneNumberRequiredAction.PROVIDER_ID;
    }

    @Override
    public String getDisplayText() {
        return "Update Mobile Number";
    }

	@Override
	public boolean isConfigurable() {
		return true;
	}

	@Override
	public List<ProviderConfigProperty> getConfigMetadata() {
		return SmsAuthenticatorFactory.getSmsAuthenticatorConfigProperties();
	}

	@Override
	public void validateConfig(KeycloakSession session, RealmModel realm, RequiredActionConfigModel config) {
		if (config == null || config.getConfig() == null) {
			return;
		}
		Map<String, String> raw = config.getConfig();
		if (!SmsRegistrationConfigResolver.isInlineSmsRegistration(raw)
			&& !(raw.containsKey("apiurl") && raw.containsKey("simulation"))) {
			return;
		}
		Map<String, String> effective = SmsRegistrationConfigResolver.materializeInlineRegistrationConfig(raw);
		if (!Boolean.parseBoolean(effective.get("simulation"))) {
			String url = effective.get("apiurl");
			if (url == null || url.isBlank()) {
				throw new ComponentValidationException("SMS API URL is required unless simulation mode is enabled.");
			}
		}
		try {
			Integer.parseInt(effective.get("length").trim());
			Integer.parseInt(effective.get("ttl").trim());
		} catch (NumberFormatException e) {
			throw new ComponentValidationException("Code length and TTL must be integers.");
		}
	}

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }

}
