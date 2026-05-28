'use strict';

const { Wallet } = require('ethers');
const crypto   = require('crypto');
const fs       = require('fs');
const path     = require('path');
const readline = require('readline');

// ─── Constants ────────────────────────────────────────────────────────────────
const WALLET_DIR  = path.join(__dirname, 'wallet');
const SALT_LEN    = 32;   // bytes – for scrypt key derivation
const IV_LEN      = 16;   // bytes – AES-256-CBC initialisation vector
const KEY_LEN     = 32;   // bytes – 256-bit AES key

// ─── Key derivation ───────────────────────────────────────────────────────────
function deriveKey(password, salt) {
  return crypto.scryptSync(password, salt, KEY_LEN, { N: 16384, r: 8, p: 1 });
}

// ─── Encryption ───────────────────────────────────────────────────────────────
// Layout of the raw buffer written to disk (before BASE64):
//   [0 .. 31]        salt  (32 bytes)
//   [32 .. 47]       IV    (16 bytes)
//   [48 .. end]      AES-256-CBC ciphertext
function encryptPrivateKey(privateKey, password) {
  const salt      = crypto.randomBytes(SALT_LEN);
  const iv        = crypto.randomBytes(IV_LEN);
  const key       = deriveKey(password, salt);

  const cipher    = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encrypted = Buffer.concat([
    cipher.update(privateKey, 'utf8'),
    cipher.final(),
  ]);

  const combined  = Buffer.concat([salt, iv, encrypted]);
  return combined.toString('base64');
}

// ─── Password prompt (no echo) ────────────────────────────────────────────────
function askPassword(prompt) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input:  process.stdin,
      output: process.stdout,
    });
    rl._writeToOutput = (s) => { if (s === prompt) rl.output.write(s); };
    rl.question(prompt, (password) => {
      rl.close();
      process.stdout.write('\n');
      resolve(password.trim());
    });
  });
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  // Prompt for password
  const password = await askPassword('Enter password: ');
  if (!password) {
    console.error('Error: Password cannot be empty.');
    process.exit(1);
  }

  // Generate a random BSC wallet (same curve as Ethereum)
  const wallet     = Wallet.createRandom();
  const address    = wallet.address;
  const privateKey = wallet.privateKey;

  // Encrypt the private key
  const encryptedBase64 = encryptPrivateKey(privateKey, password);

  // Ensure the wallet directory exists
  fs.mkdirSync(WALLET_DIR, { recursive: true });

  // Save encrypted BASE64 string to wallet/<address>.txt
  const filePath = path.join(WALLET_DIR, `${address}.txt`);
  fs.writeFileSync(filePath, encryptedBase64, 'utf8');

  console.log(`Wallet Address : ${address}`);
  console.log(`Saved to       : wallet/${address}.txt`);
}

main().catch((err) => { console.error(err.message); process.exit(1); });
