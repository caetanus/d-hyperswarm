# d-hyperswarm

A **wire-compatible** D reimplementation of [Holepunch](https://holepunch.to/)'s
peer-to-peer stack — `hyperswarm`, `hyperdht`, and `udx` — on
[vibe-core](https://github.com/vibe-d/vibe-core) fibers, with crypto on
[libsodium](https://libsodium.org). It speaks the real network's wire, so a D
node finds and connects to peers alongside the JavaScript implementation.

The aim is to build **Keet bots in D**: join a topic on the public hyperdht,
hole-punch through NATs to the other members, and hold an encrypted udx stream —
the same path Keet itself uses. (A Python binding is planned separately.)

## Status

- **Cross-NAT hole punch proven against `hyperdht` 6.34** on a real two-NAT rig,
  all three ways (D↔D, D server ↔ JS client, JS server ↔ D client): join → OPEN
  in ~1.6 s, then a full encrypted stream that survives a bulk transfer and a
  long idle hold.
- The Noise/`secret-stream` handshake, the dht-rpc layer, the NAT sampler, and
  the round-synchronised holepuncher are all ported and covered by unit tests
  plus vectors captured from the reference JS.
- `udx` is **vendored** (`vendor/libudx/`, unmodified) and built as plain C; the
  D side provides a libuv-shaped facade. Nothing but the `hs_udx_*` C-ABI surface
  crosses the boundary — see `vendor/build-libudx.sh`.

## Layout

| Path | What |
|------|------|
| `source/hyperswarm/` | the library: `dht/` (hyperdht + dht-rpc + holepunch), `udx/` (the facade + binding), `noise/`, `swarm.d`, `connection.d`, `cenc.d` |
| `vendor/libudx/` | the upstream udx C source, vendored and never edited |
| `vendor/build-libudx.sh` | builds libudx as one relocatable object with linker-level symbol isolation (host / Android arm64 / x86_64) |
| `tests/` | unit-threaded + fluent-asserts suite (`dub test`) and wire vectors |
| `interop/` | runnable peers that talk to the JS reference (see the `run-*.sh` scripts) and the `*-pipe` rig tools |
| `examples/photo-sync/` | a small file-sync demo over a punched topic connection |
| `DESIGN.md`, `notes/` | the port plan and protocol notes |

## Build & test

```sh
dub build            # the library (its preBuild compiles the vendored libudx)
dub test             # the unit + vector suite
dub build -c hs-pipe # a topic-level rig peer: join a topic, punch, burn, hold
```

`hs-pipe` is the end-to-end yardstick:

```sh
# on a public host (or one side of a two-NAT rig)
hs-pipe --role server --topic <word>
# on the other side
hs-pipe --role client --topic <word> --burn 4194304 --hold 20 --ping-every 5
```

## License

MIT — see [LICENSE](LICENSE). The vendored udx keeps its own license
(`vendor/libudx/LICENSE`).
