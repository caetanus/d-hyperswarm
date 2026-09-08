/// The crypto primitives behind hyperswarm's Noise handshake and secret-stream,
/// ported from noise-handshake (pin dc1f9c4) + noise-curve-ed (e8265e7) onto
/// libsodium. Every routine here must match the reference byte-for-byte — the
/// tests assert against vectors generated from the real JS.
///
/// Protocol: Noise_XX_Ed25519_ChaChaPoly_BLAKE2b. This module is the leaf layer:
/// BLAKE2b, HMAC-BLAKE2b, HKDF, ChaCha20-Poly1305 (IETF) and the Ed25519 DH.
module hyperswarm.noise.crypto;

import libsodium.crypto_generichash : crypto_generichash, crypto_generichash_init,
    crypto_generichash_update, crypto_generichash_final, crypto_generichash_state;
import libsodium.crypto_aead_chacha20poly1305 : crypto_aead_chacha20poly1305_ietf_encrypt,
    crypto_aead_chacha20poly1305_ietf_decrypt;
import libsodium.crypto_hash_sha512 : crypto_hash_sha512;
import libsodium.crypto_sign : crypto_sign_seed_keypair;
import libsodium.crypto_scalarmult_ed25519 : crypto_scalarmult_ed25519_noclamp;

enum size_t HASHLEN = 64; // BLAKE2b output
enum size_t BLOCKLEN = 128; // BLAKE2b block, HMAC pad width
enum size_t MACBYTES = 16; // ChaCha20-Poly1305 tag
enum size_t DHLEN = 32;
enum size_t PKLEN = 32;
enum size_t SKLEN = 64; // ed25519 sign secret key

/// BLAKE2b, 64-byte digest.
void blake2b(ref ubyte[HASHLEN] digest, scope const(ubyte)[] data) @trusted
{
    crypto_generichash(digest.ptr, HASHLEN, data.ptr, data.length, null, 0);
}

/// HMAC with BLAKE2b as the hash (noise-handshake/hmac.js): the message is the
/// concatenation of `msgs`. Standard HMAC — key padded/hashed to BLOCKLEN, ipad
/// 0x36 / opad 0x5c, two BLAKE2b passes.
void hmacBlake2b(ref ubyte[HASHLEN] outp, scope const(ubyte)[] key, scope const(ubyte)[][] msgs) @trusted
{
    ubyte[BLOCKLEN] hmacKey = 0;
    if (key.length > BLOCKLEN)
        crypto_generichash(hmacKey.ptr, HASHLEN, key.ptr, key.length, null, 0);
    else
        hmacKey[0 .. key.length] = key[];

    ubyte[BLOCKLEN] ipad = void, opad = void;
    foreach (i; 0 .. BLOCKLEN)
    {
        ipad[i] = 0x36 ^ hmacKey[i];
        opad[i] = 0x5c ^ hmacKey[i];
    }

    crypto_generichash_state st;
    // inner = BLAKE2b(ipad ++ msgs...)
    crypto_generichash_init(&st, null, 0, HASHLEN);
    crypto_generichash_update(&st, ipad.ptr, BLOCKLEN);
    foreach (m; msgs)
        crypto_generichash_update(&st, m.ptr, m.length);
    crypto_generichash_final(&st, outp.ptr, HASHLEN);
    // outer = BLAKE2b(opad ++ inner)
    crypto_generichash_init(&st, null, 0, HASHLEN);
    crypto_generichash_update(&st, opad.ptr, BLOCKLEN);
    crypto_generichash_update(&st, outp.ptr, HASHLEN);
    crypto_generichash_final(&st, outp.ptr, HASHLEN);
}

/// HKDF (RFC 5869) over HMAC-BLAKE2b, empty info — Noise's KDF. Returns
/// `nblocks * HASHLEN` bytes; callers take the 32-byte prefix of each half.
ubyte[] hkdf(scope const(ubyte)[] salt, scope const(ubyte)[] ikm, size_t nblocks) @trusted
{
    ubyte[HASHLEN] prk;
    hmacBlake2b(prk, salt, [ikm]);

    auto outp = new ubyte[](HASHLEN * nblocks);
    ubyte[HASHLEN] prev = void;
    size_t prevLen = 0;
    foreach (i; 0 .. nblocks)
    {
        ubyte[1] counter = cast(ubyte)(i + 1);
        ubyte[HASHLEN] t = void;
        hmacBlake2b(t, prk[], [prev[0 .. prevLen], counter[]]);
        outp[i * HASHLEN .. (i + 1) * HASHLEN] = t[];
        prev = t;
        prevLen = HASHLEN;
    }
    return outp;
}

/// ChaCha20-Poly1305 (IETF): 12-byte nonce, zero but for a uint32 LE counter at
/// offset 4. Returns ciphertext (plaintext length + 16).
ubyte[] chachaEncrypt(scope const(ubyte)[] key, uint counter, scope const(ubyte)[] ad, scope const(ubyte)[] pt) @trusted
in (key.length == 32)
{
    ubyte[12] nonce = 0;
    nonce[4] = cast(ubyte) counter;
    nonce[5] = cast(ubyte)(counter >> 8);
    nonce[6] = cast(ubyte)(counter >> 16);
    nonce[7] = cast(ubyte)(counter >> 24);

    auto ct = new ubyte[](pt.length + MACBYTES);
    ulong clen;
    crypto_aead_chacha20poly1305_ietf_encrypt(ct.ptr, &clen, pt.ptr, pt.length,
        ad.ptr, ad.length, null, nonce.ptr, key.ptr);
    return ct[0 .. clen];
}

/// Inverse of chachaEncrypt. Throws on authentication failure.
ubyte[] chachaDecrypt(scope const(ubyte)[] key, uint counter, scope const(ubyte)[] ad, scope const(ubyte)[] ct) @trusted
in (key.length == 32)
{
    if (ct.length < MACBYTES)
        throw new Exception("ciphertext too short");
    ubyte[12] nonce = 0;
    nonce[4] = cast(ubyte) counter;
    nonce[5] = cast(ubyte)(counter >> 8);
    nonce[6] = cast(ubyte)(counter >> 16);
    nonce[7] = cast(ubyte)(counter >> 24);

    auto pt = new ubyte[](ct.length - MACBYTES);
    ulong plen;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(pt.ptr, &plen, null, ct.ptr, ct.length,
            ad.ptr, ad.length, nonce.ptr, key.ptr) != 0)
        throw new Exception("chacha20poly1305 authentication failed");
    return pt[0 .. plen];
}

/// An Ed25519 static keypair from a 32-byte seed (crypto_sign_seed_keypair).
struct Keypair
{
    ubyte[PKLEN] publicKey;
    ubyte[SKLEN] secretKey;
}

Keypair ed25519Keypair(scope const(ubyte)[] seed) @trusted
in (seed.length == 32)
{
    Keypair kp;
    crypto_sign_seed_keypair(kp.publicKey.ptr, kp.secretKey.ptr, seed.ptr);
    return kp;
}

/// The Noise DH on the Ed25519 curve (noise-curve-ed): derive the scalar from the
/// sign secret key's seed — sha512(sk[0..32]), clamp — then scalarmult_noclamp.
/// No ed25519→x25519 conversion.
void ed25519DH(ref ubyte[DHLEN] outp, scope const(ubyte)[] publicKey, scope const(ubyte)[] secretKey) @trusted
in (publicKey.length == PKLEN && secretKey.length == SKLEN)
{
    ubyte[64] h = void;
    crypto_hash_sha512(h.ptr, secretKey.ptr, 32);
    h[0] &= 248;
    h[31] &= 127;
    h[31] |= 64;
    crypto_scalarmult_ed25519_noclamp(outp.ptr, h.ptr, publicKey.ptr);
}
