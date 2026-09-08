// A real hyperdht node (bootstrapper) so we can validate announce/lookup against
// the reference deterministically (one node stores and returns). args: <port> <readyFile>
const DHT = require('hyperdht')
const fs = require('fs')
const [port, readyFile] = process.argv.slice(2)
const node = DHT.bootstrapper(Number(port), '127.0.0.1')
node.ready().then(() => {
  console.log('HYPERDHT LISTEN port=' + node.address().port)
  fs.writeFileSync(readyFile, String(node.address().port))
})
