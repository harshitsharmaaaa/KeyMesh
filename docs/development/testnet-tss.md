# Testnet TSS — Phase 2.4

## Env

```
KEYMESH_TESTNET_RPC_URL=                # e.g. https://sepolia.infura.io/v3/...
KEYMESH_TESTNET_CHAIN_ID=11155111       # Sepolia
KEYMESH_ENABLE_TSS_TESTNET=true
KEYMESH_SIGNING_MODE=threshold          # default single
# No private keys here — use local keystore or env-provided test account
```

See `.env.example` for placeholders.

## Flow

```
forge build
→ deploy KeymeshWallet for TSS group address (derived via setup_2of3().group_public_key)
→ configure testnet (chainId, RPC)
→ init ThresholdEcdsaProvider with material
→ create KEYMESH_TX_V1 (value transfer, empty calldata)
→ PolicyManager check
→ ThresholdEcdsaProvider.sign(binding, [0,1], session_id)  (A+B)
→ verify low-s, ecrecover == group address
→ broadcast via viem, wait receipt, verify nonce+event
```

Dedicated testnet wallet per TSS group address avoids changing production semantics.

## Safety

* testnet funds only, feature flag required, mainnet rejected unless `KEYMESH_ENABLE_MAINNET_TSS=true`
* secrets not committed, deployment artifact records addresses without keys
* coordinator is local orchestration (participant discovery, session creation, relay, timeout, aggregation) — no private key, no digest/nonce bypass
