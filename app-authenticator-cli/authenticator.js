import { Command } from "commander";
import inquirer from "inquirer";
import axios from "axios";
import * as jose from "jose";
import { v4 as uuidv4 } from "uuid";
import fs from "fs/promises";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";
import * as AxiosLogger from "axios-logger";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const DATA_FILE = resolve(__dirname, "./data.json");

async function main() {
	const program = new Command();

	program
		.name("authenticator-cli")
		.description("CLI to test Keycloak authenticator API");

	program
		.command("setup")
		.description(
			"Generate an asymmetric keypair and complete authenticator setup"
		)
		.action(commandSetup);

	program
		.command("auth")
		.description(
			"poll the keycloak api for a login challenge and send reply"
		)
		.action(commandAuth);

	try {
		await program.parseAsync();
	} catch (err) {
		console.error("Commmand failed");

		if (!axios.isAxiosError(err)) {
			console.error(err);
		}
	}
}

// commands

async function commandSetup(_arg, _options) {
	const { activationTokenUrl } = await promptActivationTokenUrl();

	const url = new URL(activationTokenUrl);

	// get keycloak base url
	const [_matched, basePath, _realm] = url.pathname.match(
		/(.*\/realms\/([^\/]+))\//
	);
	const baseURL = `${url.origin}${basePath}`;

	// query parameters
	const clientId = url.searchParams.get("client_id");
	const tabId = url.searchParams.get("tab_id");
	const key = url.searchParams.get("key");

	// get user id from keycloak action token
	const { sub: userId } = await jose.decodeJwt(key);

	// prompt which signature algorithm to use and
	// generate new key pair
	const { alg } = await promptAlgorithm();
	const { publicKey, privateKey } = await jose.generateKeyPair(alg);
	const spkiPem = await jose.exportSPKI(publicKey);
	const spki = spkiPem.replace(
		/(?:-----(?:BEGIN|END) PUBLIC KEY-----|\s)/g,
		""
	);
	const authenticatorId = uuidv4();
	const client = new KeycloakClient({
		baseURL,
		privateKey,
		alg,
		authenticatorId,
		userId,
	});

	await client.setup({
		clientId,
		tabId,
		key,
		publicKey: spki,
		keyAlgorithm: mapKeyAlgorithm(alg),
		deviceOs: "unknown",
	});

	const data = {
		baseURL,
		authenticatorId,
		userId,
		alg,
		privateKey: await jose.exportJWK(privateKey),
		publicKey: await jose.exportJWK(publicKey),
	};

	await saveData(data);
}

async function commandAuth(_arg, _options) {
	const {
		baseURL,
		authenticatorId,
		userId,
		alg,
		privateKey: privateKeyJwk,
	} = await loadData();

	const privateKey = await jose.importJWK(privateKeyJwk, alg);

	const client = new KeycloakClient({
		baseURL,
		privateKey,
		alg,
		authenticatorId,
		userId,
	});

	const [challenge] = await client.getChallanges();

	if (!challenge) {
		console.log("No current login attempts");
		return;
	}

	console.log("Login Attempt", challenge);

	const { granted } = await promptGranted();

	const { codeChallenge, targetUrl } = challenge;

	const url = new URL(targetUrl);
	const clientId = url.searchParams.get("client_id");
	const tabId = url.searchParams.get("tab_id");
	const key = url.searchParams.get("key");

	await client.replyChallenge({
		clientId,
		codeChallenge,
		granted: granted.toLowerCase() === "accept",
		key,
		tabId,
	});
}

// prompts

function promptActivationTokenUrl() {
	return inquirer.prompt([
		{
			type: "string",
			name: "activationTokenUrl",
			message:
				"Enter the Activation Token Url from the Keycloak Account Console:",
		},
	]);
}

function promptAlgorithm() {
	return inquirer.prompt([
		{
			type: "list",
			name: "alg",
			message: "Select a JWK algorithm:",
			choices: ["PS256", "PS512", "ES256", "ES512"],
		},
	]);
}

function promptGranted() {
	return inquirer.prompt([
		{
			type: "list",
			name: "granted",
			message: "Accept or reject the login:",
			choices: ["Accept", "Reject"],
		},
	]);
}

// client

/**
 * @typedef {{
 *  userName: string
 *  userFirstName: string
 *  userLastName: string
 *  targetUrl: string
 *  secret: string
 *  updatedTimestamp: string
 *  ipAddress: string
 *  device: string
 *  browser: string
 *  os: string
 *  osVersion: string
 * }} ChallengeDto
 */

class KeycloakClient {
	constructor({ baseURL, privateKey, alg, authenticatorId, userId }) {
		this._authenticatorId = authenticatorId;
		this._userId = userId;
		this._privateKey = privateKey;
		this._alg = alg;

		this._client = axios.create({
			baseURL,
		});

		this._client.interceptors.request.use(AxiosLogger.requestLogger);

		this._client.interceptors.response.use(
			AxiosLogger.responseLogger,
			(err) =>
				AxiosLogger.errorLogger(err, {
					params: true,
					headers: true,
					data: true,
					status: true,
					statusText: true,
				})
		);
	}

	_createSignatureToken(payload) {
		return new jose.SignJWT(payload)
			.setProtectedHeader({
				alg: this._alg,
				kid: this._authenticatorId,
				typ: "JWT",
			})
			.setIssuedAt()
			.setExpirationTime("30s")
			.setSubject(this._userId)
			.setJti(uuidv4())
			.sign(this._privateKey);
	}

	async setup({
		clientId,
		tabId,
		key,
		deviceOs,
		devicePushId,
		publicKey,
		keyAlgorithm,
	}) {
		const jwt = await this._createSignatureToken({ typ: "app-setup-signature-token" });

		await this._client.get("/login-actions/action-token", {
			headers: {
				"x-signature": jwt,
			},
			params: {
				client_id: clientId,
				tab_id: tabId,
				key,
				authenticator_id: this._authenticatorId,
				device_os: deviceOs,
				device_push_id: devicePushId,
				public_key: publicKey,
				key_algorithm: keyAlgorithm,
			},
		});
	}

	/**
	 *
	 * @returns {Promise<ChallengeDto[]>}
	 */
	async getChallanges() {
		const jwt = await this._createSignatureToken({
			typ: "app-challenges-signature-token",
		});
		const { data: challenges } = await this._client.get("/challenges", {
			headers: {
				"x-signature": jwt,
			},
		});
		return challenges;
	}

	async replyChallenge({ clientId, tabId, key, codeChallenge, granted }) {
		const jwt = await this._createSignatureToken({
			typ: "app-auth-signature-token",
			codeChallenge,
		});

		await this._client.get("/login-actions/action-token", {
			headers: {
				"x-signature": jwt,
			},
			params: {
				client_id: clientId,
				tab_id: tabId,
				key: key,
				granted: granted,
			},
		});
	}
}

// utils

async function saveData(data) {
	await fs.writeFile(DATA_FILE, JSON.stringify(data, null, 4));
}

async function loadData() {
	return JSON.parse(await fs.readFile(DATA_FILE));
}

/**
 * map JWT signature algorithm to keycloak key algorithm
 */
function mapKeyAlgorithm(alg) {
	const valueMap = {
		PS256: "RSASSA-PSS",
		PS512: "RSASSA-PSS",
		ES256: "EC",
		ES512: "EC",
	};
	if (valueMap[alg] === undefined) {
		throw new Error(`unknown alg ${alg}`);
	}
	return valueMap[alg];
}

main();
