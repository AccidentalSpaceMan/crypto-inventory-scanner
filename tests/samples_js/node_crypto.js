// Sample: Node's crypto module (CommonJS). Never run; the scanner only reads it.
// An "expect" comment at the end of a line lists the algorithm ids that must be found there.
'use strict';

const crypto = require('crypto');
const { createHash: hash, pbkdf2Sync } = require('node:crypto');
const bcrypt = require('bcryptjs'); // expect: BCRYPT

const LEGACY_DIGEST = 'sha1';
const ITERATIONS = 1000;
const pattern = /"md5"|'sha1'/g; // a regex literal with quotes inside: not a finding

function checksum(data) {
  return crypto.createHash('md5').update(data).digest('hex'); // expect: MD5
}

function fingerprint(data) {
  return hash(LEGACY_DIGEST).update(data).digest('hex'); // expect: SHA1
}

function good(data) {
  return crypto.createHash(`sha256`).update(data).digest('hex'); // expect: SHA256
}

function storePassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex'); // expect: UNSALTED_PASSWORD_HASH
}

function tag(key, data) {
  return crypto.createHmac('sha1', key).update(data).digest(); // expect: HMAC_SHA1
}

function strongTag(key, data) {
  return crypto.createHmac('sha384', key).update(data).digest(); // expect: HMAC
}

function ecb(key, data) {
  const c = crypto.createCipheriv('aes-128-ecb', key, null); // expect: AES, ECB
  return Buffer.concat([c.update(data), c.final()]);
}

function cbcByDefault(key, iv) {
  return crypto.createCipheriv('aes256', key, iv); // expect: AES, CBC
}

function gcm(key, iv) {
  return crypto.createCipheriv('aes-256-gcm', key, iv); // expect: AES_GCM
}

function tripleDes(key) {
  return crypto.createCipheriv('des-ede3', key, null); // expect: TDES, ECB
}

function deprecated(password) {
  return crypto.createCipher('aes192', password); // expect: AES, CBC
}

function rsaKeys() {
  return crypto.generateKeyPairSync('rsa', { modulusLength: 1024 }); // expect: RSA_WEAK
}

function okRsaKeys() {
  return crypto.generateKeyPairSync('rsa', { // expect: RSA
    modulusLength: 3072, // the size is read from the options object
  }); // the finding is reported on the line where the call starts
}

function hybridParts() {
  const classical = crypto.generateKeyPairSync('x25519'); // expect: X25519
  const postQuantum = crypto.generateKeyPairSync('ml-kem-768'); // expect: MLKEM
  return [classical, postQuantum];
}

function signLegacy(data, key) {
  return crypto.createSign('RSA-SHA1').update(data).sign(key); // expect: RSA, SHA1
}

function weakKdf(password, salt) {
  return pbkdf2Sync(password, salt, ITERATIONS, 32, 'sha256'); // expect: PBKDF2
}

function strongKdf(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 600_000, 32, 'sha512'); // expect: PBKDF2_STRONG
}

function slowHash(password, salt) {
  return crypto.scryptSync(password, salt, 32); // expect: SCRYPT
}

function oldDh() {
  return crypto.getDiffieHellman('modp2'); // expect: DH_WEAK
}

function sessionToken() {
  return crypto.randomBytes(32).toString('hex'); // expect: CSPRNG
}

function insecureToken() {
  return Math.random().toString(36).slice(2); // expect: INSECURE_RANDOM
}

function shuffle(cards) {
  return cards.sort(() => Math.random() - 0.5);
}

async function hashPassword(password) {
  return bcrypt.hash(password, 12); // expect: BCRYPT
}

module.exports = { checksum, pattern };
