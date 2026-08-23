# Canonical Signed Transaction Format — KEYMESH_TX_V1

> **Status: implemented** in TypeScript, Rust, and Solidity, pinned together
> by shared cross-language test vectors. Not audited; format may still change
> with a domain-string bump before production use.

## The model

```ts
type KeymeshTransaction = {
  wallet: Address;   // 20 bytes — the only wallet allowed to execute
  chainId: bigint;   // replay separation across chains
  nonce: bigint;     // wallet-scoped, strictly sequential
  to: Address;       // 20 bytes — execution target
  value: bigint;     // wei
  data: Hex;         // calldata, length-prefixed in the encoding
  expiry: bigint;    // unix seconds; valid while now <= expiry
};
```

Every field is inside the signed message, so a signature is invalidated by
mutating anything — including the wallet and chain it was made for.

## Encoding

```
domain_tag = keccak256("KEYMESH_TX_V1")                 (32 bytes)

payload =
  domain_tag                                            (32)
| wallet            raw address bytes                   (20)
| chain_id          uint256 big-endian                  (32)
| nonce             uint256 big-endian                  (32)
| to                raw address bytes                   (20)
| value             uint256 big-endian                  (32)
| data_len          uint32 big-endian == len(data)      ( 4)
| data              raw bytes                           (len(data))
| expiry            uint256 big-endian unix seconds     (32)

digest = keccak256(payload)
```

Properties:

- **Deterministic**: fixed-width fields plus exactly one length-prefixed
  dynamic field (`data`); there is one valid byte string per transaction.
- **Unambiguous**: no field can be reinterpreted by shifting boundaries —
  the u32 length prefix makes concatenation ambiguity impossible.
- **Domain separated**: the hashed domain tag prevents signatures over this
  format from being meaningful in any other protocol; `wallet` and `chainId`
  prevent replay across wallets and chains; `nonce` prevents replay in time.
- **Ethereum-native**: keccak-256 throughout; no custom hash functions.

Numeric bounds (enforced identically in all three implementations so no
implementation accepts a transaction another would reject):

| Field   | Bound                |
| ------- | -------------------- |
| chainId | `[1, 2^64 - 1]`      |
| nonce   | `[0, 2^64 - 1]`      |
| value   | `[0, 2^128 - 1]`     |
| expiry  | `[0, 2^64 - 1]`      |
| data    | at most 131072 bytes |

## Signing

Devices sign the **raw digest** — there is no EIP-191 personal-message
prefix. The digest already contains all domain separation; wrapping it again
would create a second canonical form and split the verification surface.
Solidity recovers with OpenZeppelin `ECDSA.recover(digest, (r,s,v))`, v ∈
{27, 28}; signers MUST produce low-s signatures (RFC-6979 deterministic k via
@noble/curves on the TypeScript side).

## Reference implementations

| Language   | Location                                              | Maturity      |
| ---------- | ----------------------------------------------------- | ------------- |
| TypeScript | `packages/protocol/src/canonical.ts`                  | implemented   |
| Rust       | `crates/keymesh-core/src/transaction/mod.rs`          | implemented   |
| Solidity   | `contracts/ethereum/src/KeymeshTx.sol`                | implemented   |

The Rust core deliberately owns no asymmetric cryptography: callers hash with
its `digest()` and hand the 32 bytes to their signing provider.

## Shared test vectors

Defined once in `packages/protocol/src/vectors.ts` and asserted byte-for-byte
by `canonical.test.ts` (TS), `src/transaction/mod.rs` tests (Rust), and
`test/TransactionDigest.t.sol` (Solidity). A mismatch anywhere is a protocol
bug, not a test artifact.

### Vector 1 — eth-transfer

```
wallet  0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
chainId 31337
nonce   0
to      0x70997970C51812dc3A010C7d01b50e0d17dc79C8
value   1000000000000000000
data    0x
expiry  2000000000

domain_tag = 0x908acdd86e8726216702d8abc211b34ca12c9f1537c7180c55096e1c3be1f405
digest     = 0xef48434b4ea47252caab3312aef0d299b5970bf1c8f1bd43e71c06791ad0b66a
```

Canonical bytes (hex): see `canonicalHex` of vector 1 in `vectors.ts`; all
three test suites print/compare them directly.

### Vector 2 — zero-value calldata

```
wallet  0x14dC79964da2C08b23698B3D3cc7Ca32193d9955
chainId 11155111
nonce   7
to      0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
value   0
data    0xdeadbeefcafebabe0123456789abcdef
expiry  2000000001

digest = 0x58f52cacdeacc22a70f0e855c44e50b34348984261d9c6954c48d6f895870b58
```

### Vector 3 — mainnet-shaped (64-byte calldata)

```
wallet  0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f
chainId 1
nonce   42
to      0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc
value   123456789
data    0xaabbccdd x16
expiry  4102444800

digest = 0x645dc7006dfac3665699314be7d1a4af4f2a502d9b6099b71af0db0d8f1c0a58
```

## Changing the format

Bump the domain string (`KEYMESH_TX_V1` → `KEYMESH_TX_V2`) and regenerate:
TypeScript encoder + vectors, Rust encoder + fixture constants, Solidity
library + digest tests — in the same change. Old signatures must fail loudly
(the domain tag changes), never silently verify.
