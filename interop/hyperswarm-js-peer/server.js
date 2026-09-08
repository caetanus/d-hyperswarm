// A real hyperswarm SERVER on a topic, echoing on every connection. Topology: a
// pure bootstrapper node A stores/serves the DHT, and the hyperswarm's own node B
// bootstraps off A — so B's announce(topic) and listen(keyPair) records land on A
// and are retrievable by a lookup. A D client bootstraps off A, looks the topic up
// to discover B's public key, and connects to it (relayed through A).
// args: <port> <readyFile>
const DHT = require('hyperdht')
const Hyperswarm = require('hyperswarm')
const fs = require('fs')
const [port, readyFile] = process.argv.slice(2)

const boot = DHT.bootstrapper(Number(port), '127.0.0.1')
boot.ready().then(async () => {
  const bootPort = boot.address().port
  const bootstrap = [{ host: '127.0.0.1', port: bootPort }]
  const swarm = new Hyperswarm({ bootstrap, seed: Buffer.alloc(32, 9) })
  const topic = Buffer.alloc(32, 42)
  swarm.on('connection', (socket, info) => {
    socket.on('error', () => {})
    socket.on('data', (d) => socket.write(d)) // echo
  })
  const disc = swarm.join(topic, { server: true, client: false })
  await disc.flushed()
  fs.writeFileSync(readyFile, bootPort + ' ' + topic.toString('hex'))
  console.log('HYPERSWARM SERVER up: bootPort=' + bootPort + ' topic=' + topic.toString('hex').slice(0, 16) + '…')
})
