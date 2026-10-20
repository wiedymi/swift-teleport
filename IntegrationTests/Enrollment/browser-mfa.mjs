import { readFileSync, writeFileSync, renameSync, existsSync } from 'node:fs';
import { launchBrowser, nextOTP, api, authenticator, webauthn } from './webauthn.mjs';

let browser;
try {
  const credentials = JSON.parse(readFileSync('/run/browser-mfa/credentials.json', 'utf8'));
  const request = JSON.parse(readFileSync('/run/browser-mfa/request.json', 'utf8'));
  const url = new URL(request.url);
  if (url.origin !== new URL(process.env.PROXY_URL).origin || url.username || url.password || url.search || url.hash ||
      !/^\/web\/mfa\/browser\/[A-Za-z0-9_-]{1,256}$/.test(url.pathname)) throw new Error('Invalid browser MFA page');
  const requestID = url.pathname.split('/').at(-1);
  browser = await launchBrowser();
  const page = await browser.newPage();
  await authenticator(page, credentials.credential);
  await page.goto(process.env.PROXY_URL + '/web/login', { waitUntil: 'networkidle', timeout: 30000 });
  const session = await api(page, 'sessions/web', { user: credentials.username, pass: credentials.password,
    second_factor_token: await nextOTP(credentials.totpSeed) });
  const challenge = await api(page, 'mfa/authenticatechallenge', { browser_mfa_request_id: requestID }, session.token);
  const assertion = await webauthn(page, challenge.webauthn_challenge);
  const callback = await api(page, `mfa/browser/${requestID}`, { webauthn_response: assertion }, session.token, 'PUT');
  const target = new URL(callback);
  if (target.protocol !== 'http:' || target.hostname !== '127.0.0.1' || target.pathname !== '/callback' ||
      !target.port || target.username || target.password || target.hash ||
      target.searchParams.getAll('response').length !== 1 || [...target.searchParams.keys()].some(x => x !== 'response')) throw new Error('Invalid browser MFA callback');
  // The browser runs in Docker. Only this test relay crosses to the Mac listener.
  // The library still verifies the server's authenticated callback ciphertext.
  writeFileSync('/run/browser-mfa/callback.json.tmp', JSON.stringify({ url: callback }), { mode: 0o600 });
  renameSync('/run/browser-mfa/callback.json.tmp', '/run/browser-mfa/callback.json');
  const deadline = Date.now() + 15000;
  while (!existsSync('/run/browser-mfa/callback-status.json') && Date.now() < deadline) {
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  const result = JSON.parse(readFileSync('/run/browser-mfa/callback-status.json', 'utf8'));
  if (result.status !== 200) throw new Error('Browser MFA callback rejected');
  await browser.close();
  browser = undefined;
} catch {
  if (browser) await browser.close();
  process.stderr.write('Browser MFA test failed. No authentication data was reported.\n');
  process.exitCode = 1;
}
