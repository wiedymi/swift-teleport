import { chromium } from 'playwright-core';
import { mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { createHmac, randomBytes } from 'node:crypto';
import { lookup } from 'node:dns/promises';

function otp(seed) {
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

let browser;
let stage = 'HTTPS trust';
try {
  const trust = `${process.env.HOME}/.pki/nssdb`;
  mkdirSync(trust, { recursive: true, mode: 0o700 });
  execFileSync('certutil', ['-N', '--empty-password', '-d', `sql:${trust}`], { stdio: 'ignore' });
  execFileSync('certutil', ['-A', '-d', `sql:${trust}`, '-n', 'teleport-e2e', '-t', 'C,,', '-i', '/run/https-ca.pem'], { stdio: 'ignore' });
  const invitation = JSON.parse(readFileSync('/run/enrollment/invitation.json', 'utf8'));
  const password = randomBytes(24).toString('base64url');
  stage = 'browser startup';
  const proxyAddress = await lookup('auth-proxy', { family: 4 });
  const proxyHost = new URL(process.env.PROXY_URL).hostname;
  browser = await chromium.launch({ executablePath: '/usr/bin/chromium', headless: true,
    args: ['--no-sandbox', `--host-resolver-rules=MAP ${proxyHost} ${proxyAddress.address}`] });
  const page = await browser.newPage();
  stage = 'verified proxy page';
  await page.goto(process.env.PROXY_URL + '/web/login', { waitUntil: 'networkidle', timeout: 30000 });
  stage = 'TOTP challenge';
  const registration = await page.evaluate(async token => {
    const result = await fetch(`/v1/webapi/users/password/token/${encodeURIComponent(token)}`);
    if (!result.ok) throw new Error(`Enrollment challenge failed (${result.status})`);
    return await result.json();
  }, invitation.token);
  const png = registration.qrCode;
  stage = 'TOTP QR decoding';
  if (typeof png !== 'string' || png.length > 1024 * 1024) throw new Error('Invalid enrollment challenge');
  writeFileSync('/tmp/totp.png', Buffer.from(png, 'base64'), { mode: 0o600 });
  // QR data is a machine-readable otpauth URI. No image text recognition is used.
  const uri = new URL(execFileSync('zbarimg', ['--quiet', '--raw', '/tmp/totp.png'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim());
  rmSync('/tmp/totp.png');
  if (uri.protocol !== 'otpauth:' || uri.hostname !== 'totp') throw new Error('Invalid TOTP URI');
  const seed = uri.searchParams.get('secret');
  if (!seed) throw new Error('Enrollment response has no TOTP seed');
  const code = otp(seed);
  stage = 'password enrollment';
  await page.evaluate(async value => {
    const result = await fetch('/v1/webapi/users/password/token', {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(value),
    });
    if (!result.ok) throw new Error(`Password enrollment failed (${result.status})`);
  }, { token: invitation.token, password: Buffer.from(password).toString('base64'), second_factor_token: code, deviceName: 'e2e-totp' });
  await browser.close();
  browser = undefined;
  // Keep the enrollment code out of the native client's first OTP attempt.
  await new Promise(resolve => setTimeout(resolve, 30000 - Date.now() % 30000 + 1000));
  writeFileSync('/run/client/local-credentials.json', JSON.stringify({ username: invitation.username, password, totpSeed: seed }) + '\n', { mode: 0o600 });
  process.stdout.write('Local password and TOTP enrollment passed.\n');
} catch (error) {
  if (browser) await browser.close();
  const networkCode = String(error?.message).match(/net::ERR_[A-Z_]+/)?.[0];
  const statusCode = String(error?.message).match(/failed \(([0-9]{3})\)/)?.[1];
  process.stderr.write(`Local enrollment failed at ${stage}${networkCode ? ` (${networkCode})` : ''}${statusCode ? ` (HTTP ${statusCode})` : ''}. No credentials were reported.\n`);
  process.exitCode = 1;
}
