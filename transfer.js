'use strict';

require('dotenv').config();

const { ethers }   = require('ethers');
const crypto       = require('crypto');
const fs           = require('fs');
const path         = require('path');
const readline     = require('readline');

// ─── Encryption constants (must match generate.js) ────────────────────────────
const SALT_LEN = 32;   // bytes
const IV_LEN   = 16;   // bytes
const KEY_LEN  = 32;   // bytes (256-bit AES key)

// ─── Supported chain configuration ───────────────────────────────────────────
// RPC URLs are loaded from .env so they can be updated without touching code.
const CHAINS = {
  bsc: {
    rpc:     process.env.RPC_BSC,
    chainId: 56,
    symbol:  'BNB',
    label:   'Binance Smart Chain',
  },
  ethereum: {
    rpc:     process.env.RPC_ETH,
    chainId: 1,
    symbol:  'ETH',
    label:   'Ethereum',
  },
  polygon: {
    rpc:     process.env.RPC_POLYGON,
    chainId: 137,
    symbol:  'MATIC',
    label:   'Polygon',
  },
  arbitrum: {
    rpc:     process.env.RPC_ARBITRUM,
    chainId: 42161,
    symbol:  'ETH',
    label:   'Arbitrum One',
  },
  base: {
    rpc:     process.env.RPC_BASE,
    chainId: 8453,
    symbol:  'ETH',
    label:   'Base',
  },
  knyx: {
    rpc:     process.env.RPC_KNYX,
    chainId: 3009,
    symbol:  'KNYX',
    label:   'Knyx',
  },
  bsctestnet: {
    rpc:     process.env.RPC_BSCTESTNET,
    chainId: 97,
    symbol:  'tBNB',
    label:   'BSC Testnet',
  }
};

// ─── Minimal ERC20 ABI (only what we need) ───────────────────────────────────
const ERC20_ABI = [
  'function decimals() view returns (uint8)',
  'function symbol() view returns (string)',
  'function balanceOf(address owner) view returns (uint256)',
  'function transfer(address to, uint256 amount) returns (bool)',
];

// ─── Key derivation – must match generate.js ─────────────────────────────────
function deriveKey(password, salt) {
  return crypto.scryptSync(password, salt, KEY_LEN, { N: 16384, r: 8, p: 1 });
}

// ─── Decryption – must match generate.js ─────────────────────────────────────
// Buffer layout: [salt (32 B)][IV (16 B)][ciphertext]
function decryptPrivateKey(encryptedBase64, password) {
  const combined = Buffer.from(encryptedBase64, 'base64');

  if (combined.length <= SALT_LEN + IV_LEN) {
    throw new Error('Wallet file is corrupted or has an invalid format.');
  }

  const salt      = combined.subarray(0, SALT_LEN);
  const iv        = combined.subarray(SALT_LEN, SALT_LEN + IV_LEN);
  const encrypted = combined.subarray(SALT_LEN + IV_LEN);

  const key      = deriveKey(password, salt);
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);

  // decipher.final() throws automatically if key/padding is wrong
  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),
  ]);

  return decrypted.toString('utf8');
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

// ─── Readline confirmation helper ────────────────────────────────────────────
function askConfirmation(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input:  process.stdin,
      output: process.stdout,
    });
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim().toLowerCase());
    });
  });
}

// ─── Validation helpers ───────────────────────────────────────────────────────
function validateAddress(addr, label) {
  if (!ethers.isAddress(addr)) {
    console.error(`Error: Invalid ${label} address: "${addr}"`);
    process.exit(1);
  }
}

function validateAmount(amountStr) {
  const n = parseFloat(amountStr);
  if (isNaN(n) || n <= 0) {
    console.error(`Error: Amount must be a positive number. Got: "${amountStr}"`);
    process.exit(1);
  }
}

// ─── Parse & validate CLI arguments ──────────────────────────────────────────
function parseArgs() {
  const args = process.argv.slice(2);

  if (args.length !== 5) {
    console.error('Error: Incorrect number of arguments.\n');
    console.error('Usage:');
    console.error('  node transfer.js <wallet_address> <chain> <destination> <token_or_NATIVE> <amount>\n');
    console.error('Examples:');
    console.error('  node transfer.js 0xabc... bsc 0xdef... NATIVE 0.01');
    console.error('  node transfer.js 0xabc... bsc 0xdef... 0x55d398326f99059fF775485246999027B3197955 10\n');
    console.error(`Supported chains: ${Object.keys(CHAINS).join(', ')}`);
    process.exit(1);
  }

  const [walletAddress, chainName, destination, token, amountStr] = args;
  return { walletAddress, chainName: chainName.toLowerCase(), destination, token, amountStr };
}

// ─── Display a formatted box ──────────────────────────────────────────────────
function box(title, lines) {
  const width = 52;
  const bar   = '═'.repeat(width);
  const pad   = (s) => `  ${s}`;
  console.log(`\n╔${bar}╗`);
  console.log(`║  ${title.padEnd(width - 2)}║`);
  console.log(`╠${bar}╣`);
  for (const line of lines) console.log(`║${pad(line).padEnd(width + 2)}║`);
  console.log(`╚${bar}╝\n`);
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main() {

  // ── 1. Prompt for password ───────────────────────────────────────────────────
  const password = await askPassword('Enter password: ');
  if (!password) {
    console.error('Error: Password cannot be empty.');
    process.exit(1);
  }

  // ── 2. Parse & validate CLI arguments ────────────────────────────────────────
  const { walletAddress, chainName, destination, token, amountStr } = parseArgs();

  validateAddress(walletAddress, 'wallet');
  validateAddress(destination,  'destination');
  if (token !== 'NATIVE') validateAddress(token, 'token contract');
  validateAmount(amountStr);

  // Guard against sending to self (not strictly an error, but worth flagging)
  if (walletAddress.toLowerCase() === destination.toLowerCase()) {
    console.error('Error: Sender and destination addresses are the same.');
    process.exit(1);
  }

  // ── 3. Chain lookup ───────────────────────────────────────────────────────────
  const chain = CHAINS[chainName];
  if (!chain) {
    console.error(`Error: Unsupported chain "${chainName}".`);
    console.error(`Supported chains: ${Object.keys(CHAINS).join(', ')}`);
    process.exit(1);
  }
  if (!chain.rpc) {
    console.error(`Error: RPC URL for "${chainName}" is not set in .env`);
    console.error(`       Add: RPC_${chainName.toUpperCase()}=https://...`);
    process.exit(1);
  }

  // ── 4. Load & decrypt wallet file ─────────────────────────────────────────────
  const walletFile = path.join(__dirname, 'wallet', `${walletAddress}.txt`);
  if (!fs.existsSync(walletFile)) {
    console.error(`Error: Wallet file not found: wallet/${walletAddress}.txt`);
    process.exit(1);
  }

  let privateKey;
  try {
    const encryptedBase64 = fs.readFileSync(walletFile, 'utf8').trim();
    privateKey = decryptPrivateKey(encryptedBase64, password);
  } catch {
    console.error('Error: Decryption failed. The password is incorrect or the file is corrupted.');
    process.exit(1);
  }

  // ── 5. Connect to the chain ───────────────────────────────────────────────────
  let provider;
  try {
    provider = new ethers.JsonRpcProvider(chain.rpc);
    const network = await provider.getNetwork();
    // Verify the RPC actually serves the expected chain
    if (Number(network.chainId) !== chain.chainId) {
      console.error(`Error: RPC returned chain ID ${network.chainId}, expected ${chain.chainId} for ${chainName}.`);
      process.exit(1);
    }
  } catch (err) {
    console.error(`Error: Cannot connect to ${chainName} RPC.\n  ${err.message}`);
    process.exit(1);
  }

  // ── 6. Build wallet signer & verify ownership ────────────────────────────────
  const signer = new ethers.Wallet(privateKey, provider);

  // The decrypted private key must derive the same address the user supplied
  if (signer.address.toLowerCase() !== walletAddress.toLowerCase()) {
    console.error('Error: Decrypted private key does not match the provided wallet address.');
    process.exit(1);
  }

  // ── 7. Fetch fee data for gas estimation ──────────────────────────────────────
  let feeData;
  try {
    feeData = await provider.getFeeData();
  } catch (err) {
    console.error(`Error: Failed to fetch fee data: ${err.message}`);
    process.exit(1);
  }
  // Use gasPrice for legacy chains (BSC, Polygon); fall back to maxFeePerGas for EIP-1559
  const effectiveGasPrice = feeData.gasPrice ?? feeData.maxFeePerGas ?? 0n;

  // ── 8. Build transfer details depending on NATIVE vs ERC20 ───────────────────
  let tokenSymbol;
  let tokenDecimals;
  let rawAmount;
  let estimatedGas;
  let erc20Contract; // kept in scope for the actual send step

  if (token === 'NATIVE') {
    // ── Native transfer ────────────────────────────────────────────────────────
    tokenSymbol   = chain.symbol;
    tokenDecimals = 18;

    try {
      rawAmount = ethers.parseEther(amountStr);
    } catch {
      console.error(`Error: Cannot parse amount "${amountStr}" as a native token value.`);
      process.exit(1);
    }

    // Balance check
    const balance = await provider.getBalance(signer.address);
    if (balance < rawAmount) {
      console.error(`Error: Insufficient ${chain.symbol} balance.`);
      console.error(`  Balance : ${ethers.formatEther(balance)} ${chain.symbol}`);
      console.error(`  Required: ${amountStr} ${chain.symbol}`);
      process.exit(1);
    }

    // Gas estimate
    try {
      estimatedGas = await provider.estimateGas({
        from:  signer.address,
        to:    destination,
        value: rawAmount,
      });
    } catch (err) {
      console.error(`Error: Gas estimation failed: ${err.message}`);
      process.exit(1);
    }

  } else {
    // ── ERC20 transfer ─────────────────────────────────────────────────────────
    try {
      erc20Contract = new ethers.Contract(token, ERC20_ABI, signer);
      [tokenSymbol, tokenDecimals] = await Promise.all([
        erc20Contract.symbol(),
        erc20Contract.decimals(),
      ]);
    } catch (err) {
      console.error(`Error: Failed to read token contract at ${token}.\n  ${err.message}`);
      process.exit(1);
    }

    try {
      rawAmount = ethers.parseUnits(amountStr, tokenDecimals);
    } catch {
      console.error(`Error: Cannot parse amount "${amountStr}" for token with ${tokenDecimals} decimals.`);
      process.exit(1);
    }

    // Token balance check
    try {
      const balance = await erc20Contract.balanceOf(signer.address);
      if (balance < rawAmount) {
        console.error(`Error: Insufficient ${tokenSymbol} balance.`);
        console.error(`  Balance : ${ethers.formatUnits(balance, tokenDecimals)} ${tokenSymbol}`);
        console.error(`  Required: ${amountStr} ${tokenSymbol}`);
        process.exit(1);
      }
    } catch (err) {
      console.error(`Error: Failed to check token balance: ${err.message}`);
      process.exit(1);
    }

    // Also check native balance covers gas (rough check; exact check is after estimate)
    try {
      estimatedGas = await erc20Contract.transfer.estimateGas(destination, rawAmount);
    } catch (err) {
      console.error(`Error: Gas estimation failed: ${err.message}`);
      process.exit(1);
    }

    // Warn if native balance looks too low for gas
    const nativeBalance = await provider.getBalance(signer.address);
    const gasCost       = estimatedGas * effectiveGasPrice;
    if (nativeBalance < gasCost) {
      console.error(`Error: Insufficient ${chain.symbol} for gas fees.`);
      console.error(`  ${chain.symbol} balance : ${ethers.formatEther(nativeBalance)}`);
      console.error(`  Est. gas cost : ${ethers.formatEther(gasCost)} ${chain.symbol}`);
      process.exit(1);
    }
  }

  const estimatedGasCost = ethers.formatEther(estimatedGas * effectiveGasPrice);

  // ── 9. Confirmation screen ────────────────────────────────────────────────────
  box('TRANSFER DETAILS', [
    `Chain       : ${chain.label} (${chainName.toUpperCase()}, ID ${chain.chainId})`,
    `Sender      : ${signer.address}`,
    `Destination : ${destination}`,
    `Token       : ${tokenSymbol}${token !== 'NATIVE' ? ` (${token})` : ''}`,
    `Amount      : ${amountStr} ${tokenSymbol}`,
    `Est. Gas    : ~${estimatedGasCost} ${chain.symbol}`,
  ]);

  const answer = await askConfirmation('Confirm transfer? (yes/no): ');
  if (answer !== 'yes') {
    console.log('\nTransfer cancelled.');
    process.exit(0);
  }

  // ── 10. Execute the transfer ──────────────────────────────────────────────────
  console.log('\nSending transaction...');
  let tx;
  try {
    if (token === 'NATIVE') {
      tx = await signer.sendTransaction({
        to:    destination,
        value: rawAmount,
      });
    } else {
      tx = await erc20Contract.transfer(destination, rawAmount);
    }
  } catch (err) {
    console.error(`\nError: Transaction failed to send: ${err.message}`);
    process.exit(1);
  }

  console.log(`Transaction submitted: ${tx.hash}`);
  console.log('Waiting for confirmation...');

  // ── 11. Wait for receipt and display result ───────────────────────────────────
  let receipt;
  try {
    receipt = await tx.wait();
  } catch (err) {
    console.error(`\nError: Transaction was rejected or reverted: ${err.message}`);
    console.error(`Tx hash: ${tx.hash}`);
    process.exit(1);
  }

  const actualGasCost = ethers.formatEther(receipt.gasUsed * receipt.gasPrice);

  box('TRANSACTION SUCCESSFUL', [
    `Tx Hash     : ${receipt.hash}`,
    `Chain       : ${chain.label} (${chainName.toUpperCase()})`,
    `Block       : ${receipt.blockNumber}`,
    `Sender      : ${signer.address}`,
    `Destination : ${destination}`,
    `Token       : ${tokenSymbol}`,
    `Amount      : ${amountStr} ${tokenSymbol}`,
    `Gas Used    : ${actualGasCost} ${chain.symbol}`,
    `Status      : Confirmed`,
  ]);
}

// ─── Top-level error boundary ─────────────────────────────────────────────────
main().catch((err) => {
  console.error(`\nUnexpected error: ${err.message}`);
  process.exit(1);
});
