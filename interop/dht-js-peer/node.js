// A real dht-rpc node (bootstrapper) — it auto-answers PING and FIND_NODE. The D
// peer sends a FIND_NODE and must decode the reply. Proves our dht-rpc packet wire
// against the reference. args: <port> <readyFile>
const DHT = require('dht-rpc')
const fs = require('fs')
const [port, readyFile] = process.argv.slice(2)
const node = DHT.bootstrapper(Number(port), '127.0.0.1')
node.ready().then(() => {
  console.log('DHT-RPC LISTEN port=' + node.address().port)
  fs.writeFileSync(readyFile, String(node.address().port))
})
