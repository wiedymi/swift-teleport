import { chromium } from 'playwright-core';
import { mkdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { createHmac } from 'node:crypto';
import { lookup } from 'node:dns/promises';

export function otp(seed) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const char of seed.toUpperCase().replace(/=+$/, '')) {
    const n = alphabet.indexOf(char);
    if (n < 0) throw new Error('Invalid TOTP seed');
    bits += n.toString(2).padStart(5, '0');
  }
  const key = Buffer.from((bits.match(/.{8}/g) ?? []).map(x => parseInt(x, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const hash = createHmac('sha1', key).update(counter).digest();
  const n = hash.readUInt32BE(hash[hash.length - 1] & 15) & 0x7fffffff;
  return String(n % 1000000).padStart(6, '0');
}

export async function nextOTP(seed) {
  await new Promise(resolve => setTimeout(resolve, 30000 - Date.now() % 30000 + 1000));
  return otp(seed);
}

export async function launchBrowser() {
  const trust = `${process.env.HOME}/.pki/nssdb`;
  mkdirSync(trust, { recursive: true, mode: 0o700 });
  execFileSync('certutil', ['-N', '--empty-password', '-d', `sql:${trust}`], { stdio: 'ignore' });
  execFileSync('certutil', ['-A', '-d', `sql:${trust}`, '-n', 'teleport-e2e', '-t', 'C,,', '-i', '/run/https-ca.pem'], { stdio: 'ignore' });
  const proxyAddress = await lookup('auth-proxy', { family: 4 });
  const proxyHost = new URL(process.env.PROXY_URL).hostname;
  return await chromium.launch({ executablePath: '/usr/bin/chromium', headless: true,
    args: ['--no-sandbox', `--host-resolver-rules=MAP ${proxyHost} ${proxyAddress.address}`] });
}

export async function api(page, path, body, bearer, method = 'POST') {
  return await page.evaluate(async ({ path, body, bearer, method }) => {
    const headers = { 'Content-Type': 'application/json' };
    if (bearer) headers.Authorization = `Bearer ${bearer}`;
    const response = await fetch('/v1/webapi/' + path, { method, headers, body: JSON.stringify(body) });
    if (!response.ok) throw new Error(`Test API failed (${response.status})`);
    return await response.json();
  }, { path, body, bearer, method });
}

export async function authenticator(page, credential) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'usb', hasResidentKey: true,
      hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });
  if (credential) await cdp.send('WebAuthn.addCredential', { authenticatorId, credential });
  return { cdp, authenticatorId };
}

export async function webauthn(page, challenge, create = false) {
  return await page.evaluate(async ({ challenge, create }) => {
    const bytes = value => Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0));
    const base64 = value => btoa(String.fromCharCode(...new Uint8Array(value)))
      .replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
    const publicKey = { ...challenge.publicKey, challenge: bytes(challenge.publicKey.challenge) };
    if (create) {
      publicKey.user = { ...publicKey.user, id: bytes(publicKey.user.id) };
      if (publicKey.excludeCredentials) publicKey.excludeCredentials = publicKey.excludeCredentials.map(x => ({ ...x, id: bytes(x.id) }));
    } else if (publicKey.allowCredentials) publicKey.allowCredentials = publicKey.allowCredentials.map(x => ({ ...x, id: bytes(x.id) }));
    const value = create ? await navigator.credentials.create({ publicKey }) : await navigator.credentials.get({ publicKey });
    if (!value) throw new Error('No test WebAuthn response');
    const response = { clientDataJSON: base64(value.response.clientDataJSON) };
    if (create) response.attestationObject = base64(value.response.attestationObject);
    else {
      response.authenticatorData = base64(value.response.authenticatorData);
      response.signature = base64(value.response.signature);
      if (value.response.userHandle) response.userHandle = base64(value.response.userHandle);
    }
    return { id: value.id, rawId: base64(value.rawId), type: value.type,
      response, extensions: value.getClientExtensionResults() };
  }, { challenge, create });
}

export async function registerCredential(page, credentials) {
  const device = await authenticator(page);
  const session = await api(page, 'sessions/web', { user: credentials.username, pass: credentials.password,
    second_factor_token: await nextOTP(credentials.totpSeed) });
  const token = await api(page, 'users/privilege/token', {
    existingMfaResponse: { totp_code: await nextOTP(credentials.totpSeed) },
  }, session.token);
  if (typeof token !== 'string') throw new Error('Invalid test privilege token');
  const challenge = await api(page, `mfa/token/${encodeURIComponent(token)}/registerchallenge`,
    { deviceType: 'webauthn', deviceUsage: 'mfa' });
  const response = await webauthn(page, challenge.webauthn, true);
  await api(page, 'mfa/devices', { tokenId: token, deviceName: 'e2e-webauthn', deviceUsage: 'mfa',
    webauthnRegisterResponse: response }, session.token);
  const { credentials: registered } = await device.cdp.send('WebAuthn.getCredentials', { authenticatorId: device.authenticatorId });
  if (registered.length !== 1) throw new Error('Invalid virtual credential count');
  return registered[0];
}
