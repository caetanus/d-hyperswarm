/// The post-handshake transport cipher: sodium-secretstream's Push/Pull over
/// crypto_secretstream_xchacha20poly1305, ported from holepunchto/sodium-secretstream.
/// Each message's ciphertext is the plaintext plus ABYTES (17); the sender's 24-byte
/// header keys the receiver's Pull.
module hyperswarm.noise.secretstream;

import libsodium.crypto_secretstream_xchacha20poly1305 : crypto_secretstream_xchacha20poly1305_state,
    crypto_secretstream_xchacha20poly1305_init_push, crypto_secretstream_xchacha20poly1305_push,
    crypto_secretstream_xchacha20poly1305_init_pull, crypto_secretstream_xchacha20poly1305_pull,
    crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;

enum size_t HEADERBYTES = 24;
enum size_t KEYBYTES = 32;
enum size_t ABYTES = 17; // 1 tag byte + 16 MAC

/// Encrypting half. Its `header` (24 bytes) must reach the peer's Pull.
struct Push
{
    private crypto_secretstream_xchacha20poly1305_state st;
    ubyte[HEADERBYTES] header;

    this(scope const(ubyte)[] key) @trusted
    in (key.length == KEYBYTES)
    {
        ubyte[KEYBYTES] k = key[0 .. KEYBYTES];
        crypto_secretstream_xchacha20poly1305_init_push(&st, header, k);
    }

    ubyte[] next(scope const(ubyte)[] m) @trusted
    {
        auto c = new ubyte[](m.length + ABYTES);
        ulong clen;
        crypto_secretstream_xchacha20poly1305_push(&st, c.ptr, &clen, m.ptr, m.length,
            null, 0, crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
        return c[0 .. clen];
    }
}

/// Decrypting half. `init` with the peer's header before `next`.
struct Pull
{
    private crypto_secretstream_xchacha20poly1305_state st;
    private ubyte[KEYBYTES] key;

    this(scope const(ubyte)[] k) @safe
    in (k.length == KEYBYTES)
    {
        key[] = k[0 .. KEYBYTES];
    }

    void init(scope const(ubyte)[] header) @trusted
    in (header.length == HEADERBYTES)
    {
        ubyte[HEADERBYTES] h = header[0 .. HEADERBYTES];
        crypto_secretstream_xchacha20poly1305_init_pull(&st, h, key);
    }

    ubyte[] next(scope const(ubyte)[] c) @trusted
    {
        if (c.length < ABYTES)
            throw new Exception("secretstream: ciphertext too short");
        auto m = new ubyte[](c.length - ABYTES);
        ulong mlen;
        ubyte tag;
        if (crypto_secretstream_xchacha20poly1305_pull(&st, m.ptr, &mlen, &tag,
                c.ptr, c.length, null, 0) != 0)
            throw new Exception("secretstream: authentication failed");
        return m[0 .. mlen];
    }
}
