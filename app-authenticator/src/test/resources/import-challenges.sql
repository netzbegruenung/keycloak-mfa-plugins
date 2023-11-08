INSERT INTO APP_AUTH_CHALLENGE (id, realm_id, user_id, target_url, device_id, secret, updated_timestamp, ip_address, device, browser, os, os_version)
VALUES (random_uuid(), 'baeldung', 'a5461470-33eb-4b2d-82d4-b0484e96ad7f', 'target_url', 'test_device_id', 'secret', DATEDIFF('SECOND', DATE '1970-01-01', CURRENT_TIMESTAMP()) * 1000, 'ip_address', 'device', 'browser', 'os', 'os_version');
