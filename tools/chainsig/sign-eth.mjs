// Watchdog Chain Signatures demo — the operator NEAR account signs an
// Ethereum (Sepolia) transfer through the NEAR MPC network, gated by the
// Watchdog policy contract:
//   1. AI reviewer scores the intent (NEAR AI Cloud TEE) and attests on-chain
//   2. Watchdog contract `evaluate_tx` must return Approve
//   3. chainsig.js derives the ETH address, prepares, MPC-signs, finalizes
//   4. broadcast attempted on Sepolia (needs Sepolia ETH; signed tx is
//      still produced if the account is unfunded)
//
// Env: OPERATOR_KEY read from the near-cli keychain (never committed).

import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { createPublicClient, http, parseEther } from "viem";
import { sepolia } from "viem/chains";
import { chainAdapters, contracts } from "chainsig.js";
import * as nearAPI from "near-api-js";

const OPERATOR = "watchdog-wallet-4d8a7f.testnet";
const CONTRACT = "watchdog-policy-4d8a7f.testnet";
const MPC = "v1.signer-prod.testnet";
const PATH = "ethereum-1";
const TO = process.argv[2] || "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D";
const AMOUNT_ETH = process.argv[3] || "0.001";
const SEPOLIA_RPC = process.env.SEPOLIA_RPC || "https://ethereum-sepolia-rpc.publicnode.com";

function loadKeychain(accountId) {
  const dir = path.join(os.homedir(), ".near-credentials/testnet", accountId);
  const file = fs.readdirSync(dir).find((f) => f.startsWith("ed25519_"));
  const j = JSON.parse(fs.readFileSync(path.join(dir, file), "utf8"));
  return j.private_key;
}

function intentHash(chain, to, amount, memo) {
  return crypto.createHash("sha256").update(`${chain}|${to.toLowerCase()}|${amount}|${memo}`).digest("hex").slice(0, 40);
}

const keyPair = nearAPI.KeyPair.fromString(loadKeychain(OPERATOR));
const keyStore = new nearAPI.keyStores.InMemoryKeyStore();
await keyStore.setKey("testnet", OPERATOR, keyPair);
const near = await nearAPI.connect({ networkId: "testnet", keyStore, nodeUrl: "https://test.rpc.fastnear.com" });
const account = await near.account(OPERATOR);

// --- 1. intent hash (must match the reviewer's) --------------------
const memo = "watchdog chainsig demo";
const amountWei = parseEther(AMOUNT_ETH).toString();
const ih = intentHash("eth", TO, amountWei, memo);
console.log("intent_hash:", ih);
console.log("Review command (run first if no verdict on-chain):");
console.log(`  node ../reviewer/review.mjs --submit '{"chain":"eth","to":"${TO}","amount":"${amountWei}","token":"ETH","memo":"${memo}"}'`);

// --- 2. Policy gate (state-changing; records spend) ----------------
const evaluated = await account.functionCall({
  contractId: CONTRACT,
  methodName: "evaluate_tx",
  args: { chain: "eth", to: TO, amount: amountWei, intent_hash: ih },
  gas: 50_000_000_000_000n,
});
const decision = evaluated?.result ?? evaluated;
console.log("Watchdog decision:", decision);
if (decision !== "Approve") {
  console.log("Not approved — refusing to sign.");
  process.exit(0);
}

// --- 3. Chain Signatures -------------------------------------------
const signet = new contracts.ChainSignatureContract({ networkId: "testnet", contractId: MPC });
const publicClient = createPublicClient({ chain: sepolia, transport: http(SEPOLIA_RPC) });
const Evm = new chainAdapters.evm.EVM({ publicClient, contract: signet });

const { address, publicKey } = await Evm.deriveAddressAndPublicKey(OPERATOR, PATH);
console.log("NEAR account:", OPERATOR);
console.log("Derived ETH address:", address);
console.log("Public key:", publicKey);
const { balance } = await Evm.getBalance(address);
console.log("Sepolia balance (ETH):", Number(balance) / 1e18);

const nonce = await publicClient.getTransactionCount({ address });
const { transaction, hashesToSign } = await Evm.prepareTransactionForSigning({
  from: address,
  to: TO,
  value: parseEther(AMOUNT_ETH),
  nonce,
});
console.log("Unsigned tx prepared. Payload hash:", Buffer.from(hashesToSign[0]).toString("hex").slice(0, 32) + "…");

const signerAccount = {
  accountId: OPERATOR,
  signAndSendTransactions: async ({ transactions }) => {
    const outcomes = [];
    for (const tx of transactions) {
      const fc = tx.actions[0].functionCall || tx.actions[0];
      const outcome = await account.functionCall({
        contractId: tx.receiverId,
        methodName: fc.methodName,
        args: fc.args,
        gas: BigInt(fc.gas),
        attachedDeposit: BigInt(fc.deposit),
      });
      outcomes.push(outcome);
    }
    return outcomes;
  },
};

const rsv = await signet.sign({ payloads: hashesToSign, path: PATH, keyType: "Ecdsa", signerAccount });
console.log("MPC signature received:", JSON.stringify(rsv[0]).slice(0, 120) + "…");

const signedTx = Evm.finalizeTransactionSigning({ transaction, rsvSignatures: rsv });
console.log("Signed tx:", signedTx.slice(0, 66) + "…");

try {
  const { hash } = await Evm.broadcastTx(signedTx);
  console.log("Broadcast on Sepolia:", hash);
  console.log("Explorer: https://sepolia.etherscan.io/tx/" + hash);
  const confirmed = await account.functionCall({
    contractId: CONTRACT,
    methodName: "confirm_broadcast",
    args: {},
    gas: 30_000_000_000_000n,
  });
  console.log("confirm_broadcast recorded.");
} catch (e) {
  console.log("Broadcast skipped (account probably unfunded):", String(e.message || e).slice(0, 160));
}
