# Phase 3 — secret-stream (the exact wire)

Port of `@hyperswarm/secret-stream` (holepunchto/hyperswarm-secret-stream, pin `b022ed6`)
and its Noise engine (`noise-handshake` `dc1f9c4`, `noise-curve-ed` `e8265e7`), cloned as
siblings under `~/lab`. Protocol: **`Noise_XX_Ed25519_ChaChaPoly_BLAKE2b`**. All crypto is
libsodium. Acceptance: a secret-stream handshake + encrypted echo D⇄JS against the real JS.

## Crypto primitives (all libsodium)

- **BLAKE2b** (`crypto_generichash`), 64-byte output. HASHLEN = 64, BLOCKLEN = 128.
- **HMAC-BLAKE2b** (noise-handshake/hmac.js): standard HMAC with BLAKE2b as the hash.
  key padded/hashed to 128 bytes, ipad 0x36 / opad 0x5c, `generichash(out, ipad ++ msg…)`
  then `generichash(out, opad ++ out)`. (Use multipart generichash init/update/final.)
- **HKDF** (RFC 5869 over HMAC-BLAKE2b): `PRK = HMAC(key=salt, msg=ikm)`; expand blocks
  `T(i) = HMAC(key=PRK, msg = T(i-1) ++ info ++ byte(i))`, info = "" here. Noise uses the
  first two 32-byte halves of the 128-byte (2×HASHLEN) output.
- **Cipher = ChaCha20-Poly1305 IETF** (`crypto_aead_chacha20poly1305_ietf_*`). 12-byte
  nonce, all zero except a **uint32 little-endian counter at offset 4**; ABYTES = 16. AD is
  the running transcript digest.
- **DH = Ed25519** (noise-curve-ed): static keys are `crypto_sign` keypairs (sk 64, pk 32).
  DH derives the scalar from the seed — `sha512(sk[0..32])`, clamp `s[0]&=248; s[31]&=127;
  s[31]|=64` — then `crypto_scalarmult_ed25519_noclamp(out, scalar, pk)`. Output 32 bytes.
  NO ed25519→x25519 conversion.
- **Transport cipher = `crypto_secretstream_xchacha20poly1305`** (via sodium-secretstream's
  Push/Pull). HEADERBYTES = 24, KEYBYTES = 32, ABYTES = 17.

## Noise (SymmetricState + XX), from noise-handshake

- protocol name string = `"Noise_XX_Ed25519_ChaChaPoly_BLAKE2b"` (35 bytes). Since 35 ≤ 64,
  it is copied into the 64-byte `digest` (rest zero) rather than hashed. `chainingKey =
  copy(digest)`. Then `mixHash(prologue)` (empty for secret-stream). XX has no preshare
  tokens, so nothing else in initialise.
- `mixHash(d)`: `digest = BLAKE2b(digest ++ d)`.
- `mixKey(remote, local)`: `dh = DH(remote, local)`; `[ck, k] = hkdf(chainingKey, dh)`;
  `initialiseKey(k[0..32])` (resets cipher nonce to 0).
- `encryptAndHash(pt)`: `ct = encrypt(pt, ad=digest)`; `mixHash(ct)`; return ct. (When no
  key yet, encrypt is identity.) `decryptAndHash` mirrors it.
- `split()`: `[k1,k2] = hkdf(chainingKey, empty)`, take `[0..32]` of each.
- `final()`: initiator `tx=k1, rx=k2`; responder `tx=k2, rx=k1`. handshakeHash = digest.

XX message tokens (each message = concatenation of pushed buffers, then
`encryptAndHash(payload)`):
1. **→** `[E]`            : `e.pub` (plain) ++ encAndHash(payload)
2. **←** `[E,EE,S,ES]`    : `e.pub` ++ mixKey(ee) ++ encAndHash(s.pub) ++ encAndHash(payload)
3. **→** `[S,SE]`         : encAndHash(s.pub) ++ mixKey(se) ++ encAndHash(payload)

`S` on decode reads `PKLEN (+16 if keyed)` bytes. `mixKey` token order matters:
ES uses (initiator? e:s local vs rs/re remote) per `keyPattern`.

## secret-stream framing (index.js)

- Handshake messages ride the raw stream **length-prefixed with a 3-byte little-endian
  uint** (`writeUint24le`). The prologue passed to Noise is empty.
- After `final()`: an `IDHEADERBYTES` frame carries the secretstream **header**. The tx key
  feeds a `Push` (encrypt) whose 32-byte header is sent; the peer's `Pull.init(header)`
  keys decryption. (See index.js ~360–380: `writeUint24le(IDHEADERBYTES,…)`, `new
  Push(tx[0..KEYBYTES], …)`, `new Pull(rx[0..KEYBYTES])`.)
- Each subsequent message: `writeUint24le(len, buf)` then
  `encrypt.next(plaintext, buf+3)` — a 3-byte LE length prefix followed by the
  secretstream-encrypted payload (ciphertext = plaintext + ABYTES(17)).
- Exact header/id framing to be transcribed verbatim from index.js when implementing
  (IDHEADERBYTES, the 32-byte header subarray, offsets 3/4).

## Build order (each verifiable)

1. **HMAC-BLAKE2b + HKDF** — byte-exact vectors from noise-handshake's hmac/hkdf.
2. **ChaCha20-Poly1305-IETF cipher state** — vectors (nonce counter, AD).
3. **Ed25519 DH** — vector: fixed seeds → fixed DH output vs noise-curve-ed.
4. **Noise XX** — vectors with FIXED static AND ephemeral keys (pre-set `state.e` in the
   gen script so messages are deterministic): the 3 message bytes + final tx/rx/hash.
5. **secret-stream transport** — framing + secretstream Push/Pull.
6. **Acceptance** — handshake + encrypted echo D⇄JS vs the real @hyperswarm/secret-stream.

## Notes

- libsodium via `libsodiumd` (add the dep); confirm it exposes crypto_generichash(_init/
  update/final), crypto_aead_chacha20poly1305_ietf_*, crypto_sign_(seed_)keypair,
  crypto_hash_sha512, crypto_scalarmult_ed25519_noclamp, crypto_secretstream_*.
- Noise messages cap at 65535 bytes (cipher.js guard).
