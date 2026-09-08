// A bootstrapper + a REAL hyperswarm CLIENT joining a topic to connect to the D
// hyperswarm server announcing it. args: <bootPort> <bootReadyFile> <serverKeyFile>
const DHT = require('hyperdht')
const Hyperswarm = require('hyperswarm')
const fs = require('fs')
const [bootPort, bootReadyFile, serverKeyFile] = process.argv.slice(2)
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

const boot = DHT.bootstrapper(Number(bootPort), '127.0.0.1')
boot.ready().then(async () => {
  const port = boot.address().port
  fs.writeFileSync(bootReadyFile, String(port))
  console.error('BOOT up on ' + port)

  let hex = ''
  for (let i = 0; i < 1200 && !hex; i++) {
    try { hex = fs.readFileSync(serverKeyFile, 'utf8').trim() } catch {}
    if (!hex) await sleep(50)
  }
  if (!hex) { console.log('FAIL: no server key'); process.exit(1) }
  console.error('client joining topic to reach ' + hex.slice(0, 16) + '…')

  const topic = Buffer.alloc(32, 42)
  const swarm = new Hyperswarm({ bootstrap: [{ host: '127.0.0.1', port }] })
  let got = false
  swarm.on('connection', (socket, info) => {
    console.error('js client got a connection')
    socket.on('error', () => {})
    socket.on('data', (d) => { if (d.toString() === 'hello from js hyperswarm') got = true })
    socket.write(Buffer.from('hello from js hyperswarm'))
  })
  swarm.join(topic, { client: true, server: false })

  for (let i = 0; i < 400 && !got; i++) await sleep(50)
  console.log(got ? 'PASS JS hyperswarm client <-> D hyperswarm server' : 'FAIL no echo')
  process.exit(got ? 0 : 1)
})
