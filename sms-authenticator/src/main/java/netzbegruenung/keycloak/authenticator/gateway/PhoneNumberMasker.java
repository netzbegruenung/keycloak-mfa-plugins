/*
 * Copyright 2026 B-Sharpe
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package netzbegruenung.keycloak.authenticator.gateway;

/**
 * Masks a phone number for logs: every character except a leading '+' and the last four becomes '*',
 * so a log line can tell numbers apart without disclosing them. Four characters or fewer after the
 * '+' are masked entirely.
 */
public final class PhoneNumberMasker {

	private static final int VISIBLE_DIGITS = 4;

	private PhoneNumberMasker() {
	}

	public static String mask(String number) {
		if (number == null) {
			return null;
		}
		String prefix = number.startsWith("+") ? "+" : "";
		String body = number.substring(prefix.length());
		if (body.length() <= VISIBLE_DIGITS) {
			return prefix + "*".repeat(body.length());
		}
		int hidden = body.length() - VISIBLE_DIGITS;
		return prefix + "*".repeat(hidden) + body.substring(hidden);
	}
}
