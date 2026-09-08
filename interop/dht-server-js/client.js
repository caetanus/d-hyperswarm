// A bootstrapper + a REAL hyperdht client that connects to the D server by public
// key. The D server announces itself to the bootstrapper; the client finds it via
// FIND_PEER and the bootstrapper relays the PEER_HANDSHAKE to the D server.
// args: <bootPort> <bootReadyFile> <serverKeyFile>
const DHT = require('hyperdht')
const fs = require('fs')
const [bootPort, bootReadyFile, serverKeyFile] = process.argv.slice(2)
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

const boot = DHT.bootstrapper(Number(bootPort), '127.0.0.1')
boot.ready().then(async () => {
  const port = boot.address().port
  fs.writeFileSync(bootReadyFile, String(port))
  console.error('BOOT up on ' + port)

  let hex = ''
  for (let i = 0; i < 1000 && !hex; i++) {
    try { hex = fs.readFileSync(serverKeyFile, 'utf8').trim() } catch {}
    if (!hex) await sleep(50)
  }
  if (!hex) { console.log('FAIL: no server key'); process.exit(1) }
  const pubkey = Buffer.from(hex, 'hex')
  console.error('client connecting to ' + hex.slice(0, 16) + '…')

  const node = new DHT({ bootstrap: [{ host: '127.0.0.1', port }] })
  const socket = node.connect(pubkey)
  let got = false
  socket.on('open', () => { console.error('client socket open'); socket.write(Buffer.from('hello from js client')) })
  socket.on('data', (d) => { if (d.toString() === 'hello from js client') { got = true } })
  socket.on('error', (e) => console.error('client err: ' + e.message))

  for (let i = 0; i < 300 && !got; i++) await sleep(50)
  console.log(got ? 'PASS JS client <-> D server encrypted echo' : 'FAIL no echo')
  process.exit(got ? 0 : 1)
})
