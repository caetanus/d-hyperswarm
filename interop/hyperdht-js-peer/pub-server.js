// Reference hyperdht SERVER on the PUBLIC network (default bootstrap), listening on a
// key pair derived from a seed, speaking the dht-pipe protocol: [8-byte size]+bytes
// -> ack 0x01; "PING" -> "PONG".  args: <seed>
const DHT = require('hyperdht')
const b4a = require('b4a')
const seed = b4a.alloc(32, Number(process.argv[2] || 7))
const t0 = Date.now(); const st = () => `[t+${((Date.now() - t0) / 1000).toFixed(3)}s]`
const dht = new DHT()
const keyPair = DHT.keyPair(seed)
const server = dht.createServer((sock) => {
  console.log(st(), 'OPEN: connection from', b4a.toString(sock.remotePublicKey, 'hex').slice(0, 16) + '…')
  let burn = 0, got = 0, hdr = b4a.alloc(0)
  sock.on('data', (m) => {
    if (m.length >= 4 && m.toString('latin1', 0, 4) === 'PING') { sock.write('PONG'); return }
    if (burn === 0) {
      hdr = b4a.concat([hdr, m]); if (hdr.length < 8) return
      burn = Number(hdr.readBigUInt64BE(0)); m = hdr.subarray(8); hdr = b4a.alloc(0)
      console.log(st(), 'burn of', burn, 'bytes announced')
    }
    got += m.length
    if (burn && got >= burn) { console.log(st(), 'burn complete:', got, 'bytes — acking'); sock.write(b4a.from([1])); burn = 0; got = 0 }
  })
  sock.on('close', () => console.log(st(), 'connection closed'))
  sock.on('error', (e) => console.log(st(), 'connection error', e.message))
})
server.listen(keyPair).then(() => {
  console.log(st(), 'LISTENING: key', b4a.toString(keyPair.publicKey, 'hex'))
})
