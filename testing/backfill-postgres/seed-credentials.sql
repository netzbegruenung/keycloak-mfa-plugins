-- Seeds 4000 pre-existing APP_CREDENTIAL rows that predate the AppAuthCredentialIndex table,
-- to exercise AppAuthCredentialIndexJpaEntityProviderFactory's startup backfill
-- (app-authenticator/src/main/java/netzbegruenung/keycloak/app/jpa/AppAuthCredentialIndexJpaEntityProviderFactory.java).
--
-- Run this against the 'keycloak' database AFTER Keycloak's first boot has created its schema
-- (so credential/realm/user_entity/app_auth_credential_index all exist) and WHILE Keycloak is
-- stopped, so the rows are in place, unindexed, before the next boot's postInit backfill runs.
--
-- Attaches all 4000 credentials to the default 'admin' user in the 'master' realm (both created
-- automatically by Keycloak on first boot from the KEYCLOAK_ADMIN/KEYCLOAK_ADMIN_PASSWORD env vars).
-- Each row gets a unique device_id (seed-device-1 .. seed-device-4000), required since the target
-- app_auth_credential_index table has a unique constraint on (realm_id, device_id).

DO $$
DECLARE
    target_user_id VARCHAR(36);
BEGIN
    SELECT id INTO target_user_id FROM user_entity WHERE username = 'admin';

    IF target_user_id IS NULL THEN
        RAISE EXCEPTION 'No user_entity row with username=admin found - has Keycloak booted at least once?';
    END IF;

    INSERT INTO credential (id, type, user_id, created_date, user_label, secret_data, credential_data, priority)
    SELECT
        gen_random_uuid()::text,
        'APP_CREDENTIAL',
        target_user_id,
        (extract(epoch from now()) * 1000)::bigint,
        'seed-device-' || i,
        '{}',
        json_build_object(
            'publicKey', 'dummy-public-key-' || i,
            'deviceId', 'seed-device-' || i,
            'deviceOs', 'android',
            'keyAlgorithm', 'EC',
            'signatureAlgorithm', 'SHA256withECDSA',
            'devicePushId', NULL
        )::text,
        10
    FROM generate_series(1, 4000) AS i;
END $$;
