'use strict';

require('dotenv').config();

const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

// ─── Constants ────────────────────────────────────────────────────────────────
const WALLET_DIR = path.join(__dirname, 'wallet');
const SALT_LEN   = 32;
const IV_LEN     = 16;
const KEY_LEN    = 32;

// Ethereum / BSC address: 0x + 40 hex characters
const ADDRESS_REGEX = /^0x[0-9a-fA-F]{40}$/;

// ─── Key derivation ───────────────────────────────────────────────────────────
function deriveKey(password, salt) {
  return crypto.scryptSync(password, salt, KEY_LEN, { N: 16384, r: 8, p: 1 });
}

// ─── Decryption ───────────────────────────────────────────────────────────────
// Expected buffer layout:
//   [0 .. 31]        salt  (32 bytes)
//   [32 .. 47]       IV    (16 bytes)
//   [48 .. end]      AES-256-CBC ciphertext
function decryptPrivateKey(encryptedBase64, password) {
  const combined  = Buffer.from(encryptedBase64, 'base64');

  if (combined.length <= SALT_LEN + IV_LEN) {
    throw new Error('Wallet file is corrupted or has an invalid format.');
  }

  const salt      = combined.subarray(0, SALT_LEN);
  const iv        = combined.subarray(SALT_LEN, SALT_LEN + IV_LEN);
  const encrypted = combined.subarray(SALT_LEN + IV_LEN);

  const key       = deriveKey(password, salt);
  const decipher  = crypto.createDecipheriv('aes-256-cbc', key, iv);

  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),   // throws if padding / key is wrong
  ]);

  return decrypted.toString('utf8');
}

// ─── Main ─────────────────────────────────────────────────────────────────────
function main() {
  // Validate environment
  const password = process.env.PASSWORD;
  if (!password || password.trim() === '') {
    console.error('Error: PASSWORD is not set in the .env file.');
    process.exit(1);
  }

  // Validate CLI argument
  const walletAddress = process.argv[2];
  if (!walletAddress) {
    console.error('Error: No wallet address provided.');
    console.error('Usage : node original.js <wallet_address>');
    console.error('Example: node original.js 0x1234567890abcdef1234567890abcdef12345678');
    process.exit(1);
  }

  if (!ADDRESS_REGEX.test(walletAddress)) {
    console.error('Error: Invalid wallet address format.');
    console.error('       Expected 0x followed by exactly 40 hexadecimal characters.');
    process.exit(1);
  }

  // Read wallet file
  const filePath = path.join(WALLET_DIR, `${walletAddress}.txt`);
  if (!fs.existsSync(filePath)) {
    console.error(`Error: Wallet file not found: wallet/${walletAddress}.txt`);
    process.exit(1);
  }

  const encryptedBase64 = fs.readFileSync(filePath, 'utf8').trim();

  // Decrypt
  try {
    const privateKey = decryptPrivateKey(encryptedBase64, password);
    console.log(`Wallet Address : ${walletAddress}`);
    console.log(`Private Key    : ${privateKey}`);
  } catch {
    console.error('Error: Decryption failed. The password is incorrect or the file is corrupted.');
    process.exit(1);
  }
}

main();
