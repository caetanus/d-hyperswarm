// A real hyperdht SERVER: a bootstrapper that also listens on a keyPair and echoes.
// The D client connects to keyPair.publicKey and must complete the IK peer handshake.
// args: <port> <readyFile>
const DHT = require('hyperdht')
const fs = require('fs')
const [port, readyFile] = process.argv.slice(2)
const node = DHT.bootstrapper(Number(port), '127.0.0.1')
node.ready().then(async () => {
  const keyPair = DHT.keyPair(Buffer.alloc(32, 7))
  const server = node.createServer((socket) => {
    socket.on('data', (d) => socket.write(d)) // echo
    socket.on('error', () => {})
  })
  await server.listen(keyPair)
  fs.writeFileSync(readyFile, node.address().port + ' ' + keyPair.publicKey.toString('hex'))
  console.log('HYPERDHT SERVER up: pubkey=' + keyPair.publicKey.toString('hex').slice(0, 16) + '… port=' + node.address().port)
})
