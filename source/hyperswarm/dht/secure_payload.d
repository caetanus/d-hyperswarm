/// Encrypts the holepunch payload carried in PEER_HOLEPUNCH messages. Port of
/// hyperdht/lib/secure-payload.js: the payload is sealed with crypto_secretbox
/// under the per-connection holepunchSecret (BLAKE2b(NS.PEER_HOLEPUNCH,
/// handshakeHash) — already established by the Noise handshake and exposed as
/// HandshakeResult.holepunchSecret), so only the two peers who did the handshake
/// can read or forge a punch round. Wire: [nonce(24)][ciphertext + mac(16)].
///
/// It also mints per-address tokens (keyed BLAKE2b of the peer's host with a
/// random per-puncher secret) that prove a round belongs to a specific address.
module hyperswarm.dht.secure_payload;

import std.typecons : Nullable, nullable;

import libsodium.crypto_secretbox : crypto_secretbox_easy, crypto_secretbox_open_easy;
import libsodium.randombytes : randombytes_buf;

import hyperswarm.cenc : Address;
import hyperswarm.dht.connect_messages : HolepunchPayload, encodeHolepunchPayload, decodeHolepunchPayload;
import hyperswarm.noise.crypto : keyedBlake2b;

private enum size_t NONCE = 24;
private enum size_t MAC = 16;

final class SecurePayload
{
    private ubyte[32] sharedSecret;
    private ubyte[32] localSecret;

    this(ubyte[32] holepunchSecret)
    {
        sharedSecret = holepunchSecret;
        randombytes_buf(localSecret.ptr, localSecret.length);
    }

    /// Seal a payload: [nonce][secretbox(payload)].
    ubyte[] encrypt(HolepunchPayload p)
    {
        auto msg = encodeHolepunchPayload(p);
        auto buffer = new ubyte[NONCE + msg.length + MAC];
        randombytes_buf(buffer.ptr, NONCE);
        crypto_secretbox_easy(buffer.ptr + NONCE, msg.ptr, msg.length, buffer.ptr, sharedSecret.ptr);
        return buffer;
    }

    /// Open a sealed payload; null if the box doesn't authenticate (wrong secret,
    /// tampered, or truncated) or the plaintext doesn't decode.
    Nullable!HolepunchPayload decrypt(scope const(ubyte)[] buffer)
    {
        if (buffer.length <= NONCE + MAC)
            return Nullable!HolepunchPayload.init;
        immutable cipherLen = buffer.length - NONCE;
        auto msg = new ubyte[cipherLen - MAC];
        if (crypto_secretbox_open_easy(msg.ptr, buffer.ptr + NONCE, cipherLen, buffer.ptr, sharedSecret.ptr) != 0)
            return Nullable!HolepunchPayload.init;
        try
            return nullable(decodeHolepunchPayload(msg));
        catch (Exception)
            return Nullable!HolepunchPayload.init;
    }

    /// A 32-byte token binding `addr` to this puncher: keyed BLAKE2b of the host
    /// under our per-puncher secret. Stable for the same host within one puncher.
    ubyte[] token(Address addr)
    {
        auto out_ = new ubyte[32];
        keyedBlake2b(out_, cast(const(ubyte)[]) addr.host, localSecret[]);
        return out_;
    }
}
