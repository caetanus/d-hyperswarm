// Reference hyperdht CLIENT on the PUBLIC network: connect to <keyHex>, burn <bytes>
// and hold with pings, dht-pipe protocol.  args: <keyHex> [burn] [holdSecs] [pingEvery]
const DHT = require('hyperdht')
const b4a = require('b4a')
const [keyHex, burnArg, holdArg, everyArg] = process.argv.slice(2)
const burn = Number(burnArg || 0), hold = Number(holdArg || 0), every = Number(everyArg || 10)
const t0 = Date.now(); const st = () => `[t+${((Date.now() - t0) / 1000).toFixed(3)}s]`
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const dht = new DHT()
const HyperDHTAddress = require('hyperdht-address')
// hyperdht 6.x takes a hyperdht-address (key + optional relay nodes), not a bare key
const sock = dht.connect(HyperDHTAddress.encode(b4a.from(keyHex, 'hex'), []))
let acked = false, pong = 0, closed = false
sock.on('data', (m) => { if (m[0] === 1 && m.length === 1) acked = true; else if (m.toString('latin1', 0, 4) === 'PONG') pong++ })
sock.on('close', () => { closed = true })
sock.on('error', (e) => { console.log(st(), 'FAIL:', e.message) })
sock.once('open', async () => {
  console.log(st(), 'OPEN: connected (via the DHT rendezvous)', sock.rawStream ? `${sock.rawStream.remoteHost}:${sock.rawStream.remotePort}` : '')
  let ok = true
  if (burn) {
    const tb = Date.now()
    const hdr = b4a.alloc(8); hdr.writeBigUInt64BE(BigInt(burn))
    sock.write(hdr)
    const chunk = b4a.alloc(65536, 0x42)
    let sent = 0
    while (sent < burn) { const n = Math.min(chunk.length, burn - sent); if (!sock.write(chunk.subarray(0, n))) await new Promise((r) => sock.once('drain', r)); sent += n }
    const dl = Date.now() + 120000
    while (!acked && !closed && Date.now() < dl) await sleep(20)
    if (acked) console.log(st(), 'BURN PASS:', burn, 'bytes acked in', Date.now() - tb, 'ms')
    else { console.log(st(), 'BURN FAIL after', sent, 'bytes'); ok = false }
  }
  if (hold && ok) {
    console.log('HOLD:', hold + 's, ping every', every + 's')
    const end = Date.now() + hold * 1000
    while (true) {
      const next = Date.now() + every * 1000
      while (Date.now() < next && Date.now() < end && !closed) await sleep(50)
      const before = pong, tp = Date.now(); sock.write('PING')
      while (pong === before && !closed && Date.now() < tp + 5000) await sleep(5)
      if (pong === before) { console.log(st(), 'PING FAILED'); ok = false; break }
      console.log(st(), 'ping ok, rtt', Date.now() - tp, 'ms')
      if (Date.now() >= end) break
    }
    console.log(ok ? 'HOLD PASS: the pipe stayed usable for the whole hold' : 'HOLD FAIL')
  }
  sock.end(); await sleep(500); process.exit(ok ? 0 : 1)
})
