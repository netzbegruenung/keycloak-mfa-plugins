package netzbegruenung.keycloak.authenticator;

import org.jboss.logging.Logger;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RequiredActionProviderModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Resolves SMS settings for required actions (mobile number capture and validation). Those run outside
 * an authentication execution, so they cannot use {@code AuthenticationFlowContext#getAuthenticatorConfig()}.
 * <p>
 * <strong>Inline mode (new)</strong>: set SMS fields on the &quot;Update Mobile Number&quot; required action
 * (Authentication → Required actions → settings). When {@link #isInlineSmsRegistration(Map)} is true ({@code apiurl}
 * or {@code simulation=true}), registration uses only that map (defaults fill other keys). Legacy alias config is
 * not merged in. Partial edits (e.g. code length only) keep using the legacy alias.
 * <p>
 * <strong>Legacy fallback</strong>: otherwise load the realm {@linkplain AuthenticatorConfigModel authenticator config}
 * with alias {@value #LEGACY_DEFAULT_ALIAS} (historical default used when creating the SMS step in a flow).
 */
public final class SmsRegistrationConfigResolver {

	private static final Logger logger = Logger.getLogger(SmsRegistrationConfigResolver.class);

	public static final String LEGACY_DEFAULT_ALIAS = "sms-2fa";

	/** Factory defaults for OTP length and TTL when absent from the resolved config. */
	public static final String DEFAULT_LENGTH = "6";
	public static final String DEFAULT_TTL_SECONDS = "300";

	private SmsRegistrationConfigResolver() {}

	/**
	 * {@code true} when the required-action map is a complete enough Option A setup to run registration
	 * without the legacy flow alias {@value #LEGACY_DEFAULT_ALIAS}. Requires {@code apiurl} or explicit
	 * {@code simulation=true}; {@code length} / {@code ttl} alone do not enable inline mode (legacy config
	 * is still used for those partial edits).
	 */
	public static boolean isInlineSmsRegistration(Map<String, String> ra) {
		if (ra == null || ra.isEmpty()) {
			return false;
		}
		if (hasNonBlank(ra, "apiurl")) {
			return true;
		}
		return Boolean.parseBoolean(ra.get("simulation"));
	}

	private static boolean hasNonBlank(Map<String, String> m, String k) {
		String v = m.get(k);
		return v != null && !v.isBlank();
	}

	/** Raw config from the &quot;Update Mobile Number&quot; required action (empty map if none). */
	public static Map<String, String> readPhoneNumberRequiredActionConfig(RealmModel realm) {
		Map<String, String> cfg = realm.getRequiredActionProvidersStream()
			.filter(p -> PhoneNumberRequiredAction.PROVIDER_ID.equals(p.getProviderId()))
			.findFirst()
			.map(RequiredActionProviderModel::getConfig)
			.orElse(null);
		if (cfg == null || cfg.isEmpty()) {
			return Map.of();
		}
		return new HashMap<>(cfg);
	}

	public static Map<String, String> getMergedRegistrationConfig(RealmModel realm) {
		Map<String, String> ra = readPhoneNumberRequiredActionConfig(realm);
		Map<String, String> merged = new HashMap<>();
		if (isInlineSmsRegistration(ra)) {
			merged.putAll(buildInlineRegistrationConfig(ra));
		} else {
			AuthenticatorConfigModel acm = realm.getAuthenticatorConfigByAlias(LEGACY_DEFAULT_ALIAS);
			if (acm != null && acm.getConfig() != null) {
				merged.putAll(acm.getConfig());
			}
		}
		ensureOtpLengthAndTtlDefaults(merged);
		return Collections.unmodifiableMap(merged);
	}

	/** Legacy configs may omit keys present in the admin UI by default; align with {@link SmsAuthenticatorFactory} defaults. */
	private static void ensureOtpLengthAndTtlDefaults(Map<String, String> merged) {
		if (merged.isEmpty()) {
			return;
		}
		String length = merged.get("length");
		if (length == null || length.isBlank()) {
			merged.put("length", DEFAULT_LENGTH);
		}
		String ttl = merged.get("ttl");
		if (ttl == null || ttl.isBlank()) {
			merged.put("ttl", DEFAULT_TTL_SECONDS);
		}
	}

	/**
	 * Logs a WARN when the realm still relies on the flow-bound authenticator config {@value #LEGACY_DEFAULT_ALIAS}
	 * for SMS base settings instead of inline fields on the &quot;Update Mobile Number&quot; required action.
	 * Intended to be invoked before each outbound SMS so operators notice legacy setups.
	 */
	public static void logWarningIfUsingLegacySmsAuthenticatorConfig(RealmModel realm) {
		if (isInlineSmsRegistration(readPhoneNumberRequiredActionConfig(realm))) {
			return;
		}
		AuthenticatorConfigModel legacy = realm.getAuthenticatorConfigByAlias(LEGACY_DEFAULT_ALIAS);
		if (legacy == null || legacy.getConfig() == null || legacy.getConfig().isEmpty()) {
			return;
		}
		logger.warnf(
			"SMS authenticator plugin: realm \"%s\" still uses legacy authenticator config alias \"%s\" for SMS settings. "
				+ "Migrate to inline settings on required action \"Update Mobile Number\" (Authentication → Required actions → gear icon) to avoid depending on a flow alias.",
			realm.getName(),
			LEGACY_DEFAULT_ALIAS
		);
	}

	/**
	 * Effective SMS key/value map for a browser-flow (or other) execution: starts from the same source as
	 * registration ({@link #getMergedRegistrationConfig(RealmModel)}), then applies the execution-bound
	 * authenticator config on top when present (only non-blank execution values override the base).
	 */
	public static Map<String, String> getEffectiveSmsConfigForExecution(RealmModel realm, AuthenticatorConfigModel executionConfig) {
		Map<String, String> eff = new HashMap<>(getMergedRegistrationConfig(realm));
		if (executionConfig != null && executionConfig.getConfig() != null) {
			executionConfig.getConfig().forEach((k, v) -> {
				if (v != null && !v.isBlank()) {
					eff.put(k, v);
				}
			});
		}
		return Collections.unmodifiableMap(eff);
	}

	/**
	 * Applies {@link SmsAuthenticatorFactory} defaults to a required-action map (same as at runtime for inline mode).
	 * Used by admin validation so checks match execution behavior.
	 */
	public static Map<String, String> materializeInlineRegistrationConfig(Map<String, String> ra) {
		return buildInlineRegistrationConfig(ra);
	}

	private static Map<String, String> buildInlineRegistrationConfig(Map<String, String> ra) {
		Map<String, String> out = new HashMap<>();
		for (ProviderConfigProperty p : SmsAuthenticatorFactory.getSmsAuthenticatorConfigProperties()) {
			String k = p.getName();
			if (p.getType() == ProviderConfigProperty.ROLE_TYPE) {
				String v = ra.get(k);
				if (v != null && !v.isBlank()) {
					out.put(k, v);
				}
				continue;
			}
			String v = ra.get(k);
			if (v != null && !v.isBlank()) {
				out.put(k, v);
			} else if ("apiurl".equals(k) && v != null && v.isEmpty()) {
				out.put(k, "");
			} else {
				Object d = p.getDefaultValue();
				if (d == null || d instanceof List) {
					out.put(k, "");
				} else {
					out.put(k, String.valueOf(d));
				}
			}
		}
		return out;
	}
}
