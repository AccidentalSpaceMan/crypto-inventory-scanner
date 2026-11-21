// Sample: TypeScript with JWTs, crypto-js and TLS settings. Never run; the scanner only reads it.
import jwt from 'jsonwebtoken';
import { sign as signToken } from 'jsonwebtoken';
import * as nodeCrypto from 'node:crypto';
import CryptoJS from 'crypto-js';
import md5 from 'crypto-js/md5'; // expect: MD5
import https from 'https';

const SECRET_ALG: string = 'HS256';

export function unsignedToken(payload: object): string {
  return jwt.sign(payload, '', { algorithm: 'none' }); // expect: JWT_NONE
}

export function acceptsUnsigned(token: string) {
  return jwt.verify(token, '', { algorithms: ['none', 'HS256'] }); // expect: JWT_NONE, HMAC
}

export function hmacToken(payload: object, secret: string): string {
  return signToken(payload, secret, { algorithm: SECRET_ALG }); // expect: HMAC
}

export function ecToken(payload: object, key: string): string {
  return jwt.sign(payload, key, { algorithm: 'ES256', expiresIn: '1h' }); // expect: ECC
}

export function legacyHash(data: string): string {
  return CryptoJS.MD5(data).toString(); // expect: MD5
}

export function legacyEncrypt(data: string, key: string): string {
  return CryptoJS.DES.encrypt(data, key, { mode: CryptoJS.mode.ECB }).toString(); // expect: DES, ECB
}

export function signedPayload(data: string, key: string): string {
  return CryptoJS.HmacSHA256(data, key).toString(); // expect: HMAC
}

export function digest(data: string): string {
  return nodeCrypto.createHash('sha3-256').update(data).digest('hex'); // expect: SHA3
}

export const insecureAgent = new https.Agent({ rejectUnauthorized: false }); // expect: TLS_NO_VERIFY

export const oldTlsAgent = new https.Agent({ minVersion: 'TLSv1' }); // expect: TLS_OLD

export const modernAgent = new https.Agent({ minVersion: 'TLSv1.3' }); // expect: TLS_MODERN

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; // expect: TLS_NO_VERIFY

export function apiKey(): string {
  const key = Math.floor(Math.random() * 1e16).toString(16); // expect: INSECURE_RANDOM
  return key;
}

export const help = `Never use crypto.createHash('md5') or jwt.sign(p, s, { algorithm: 'none' }).`;

export function unrelated(md5Sum: string) {
  return md5Sum.length;
}
