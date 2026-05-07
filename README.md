# SafeWallet

BSC wallet generator with AES-256-CBC encrypted private key storage.

## Project Structure

```
SafeWallet/
├── wallet/          # Generated wallet files (*.txt) — git-ignored
├── generate.js      # Generates a new wallet and saves encrypted private key
├── original.js      # Reads and decrypts a wallet's private key
├── .env             # Your secret password (never commit this)
├── .env.example     # Template for .env
├── package.json
└── README.md
```

## Installation

```bash
npm install
```

## Configuration

Copy `.env.example` to `.env` and set a strong password:

```bash
cp .env.example .env
```

`.env`:
```
PASSWORD=your_secure_password
```

> Use a long, random password. This is the only protection for your private keys.

---

## Usage

### 1 – Generate a new BSC wallet

```bash
node generate.js
```

**Example output:**
```
Wallet Address : 0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B
Saved to       : wallet/0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B.txt
```

The encrypted private key is stored inside `wallet/<address>.txt` as a BASE64 string.

---

### 2 – Retrieve the original private key

```bash
node original.js <wallet_address>
```

**Example:**
```bash
node original.js 0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B
```

**Example output:**
```
Wallet Address : 0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B
Private Key    : 0xabcdef1234567890...
```

---

## Encryption Details

| Property       | Value                              |
|----------------|------------------------------------|
| Algorithm      | AES-256-CBC                        |
| Key derivation | scrypt (N=16384, r=8, p=1)         |
| Salt           | 32 random bytes (per wallet)       |
| IV             | 16 random bytes (per wallet)       |
| Output format  | BASE64                             |

**Encrypted file layout (binary before BASE64):**

```
[ salt (32 bytes) ][ IV (16 bytes) ][ ciphertext ]
```

The salt and IV are random and unique per wallet, stored together with the ciphertext so decryption is fully self-contained from the file alone.

---

## Security Notes

- **Never share your `.env` file or `wallet/*.txt` files.**
- The `wallet/` directory and `.env` are excluded from git via `.gitignore`.
- Without the correct `PASSWORD`, the private key cannot be recovered.
- Use a strong, unique password – consider a password manager.
- Back up both the wallet `.txt` files and your password independently and securely.
- Private keys grant full control of the wallet's funds. Treat them like cash.


### 3 – Transfer tokens from the wallet

Implement chain configuration mapping:
bsc
ethereum
polygon
arbitrum
base

```
node transfer.js <wallet_address> <chain> <destination> <token_or_NATIVE> <amount>
```

```
node transfer.js 0xYourWallet bsc 0xDestination NATIVE 0.01
```

```
node transfer.js 0xYourWallet bsc 0xDestination 0x55d398326f99059fF775485246999027B3197955 10
```