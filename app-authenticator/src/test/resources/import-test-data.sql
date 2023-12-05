INSERT INTO APP_AUTH_CHALLENGE
VALUES (
		random_uuid(),
    	'baeldung',
        'a5461470-33eb-4b2d-82d4-b0484e96ad7f',
        'target_url',
        'test_device_id',
        'secret',
        DATEDIFF('SECOND', DATE '1970-01-01', CURRENT_TIMESTAMP()) * 1000,
        'ip_address',
        'device',
        'browser',
        'os',
        'os_version',
		'12eebf0b-a3eb-49f8-9ecf-173cf8a00145'
		);

INSERT INTO CREDENTIAL
VALUES (
		random_uuid(),
		null,
		'APP_CREDENTIAL',
		'a5461470-33eb-4b2d-82d4-b0484e96ad7f',
		DATEDIFF('SECOND', DATE '1970-01-01', CURRENT_TIMESTAMP()) * 1000,
		null,
		null,
		'{"publicKey":"MCowBQYDK2VwAyEAyGcPE5TNqGYHeGFVOx2skuo6imkIdoAUppmDp8ug7T0=","deviceId":"test_device_id","deviceOs":"device_os","keyAlgorithm":"Ed25519","signatureAlgorithm":"Ed25519"}',
    	20
		);
