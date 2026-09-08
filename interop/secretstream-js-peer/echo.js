// A secret-stream echo peer on the REAL @hyperswarm/secret-stream, over a plain
// TCP socket. It is the responder: it accepts a connection, runs the Noise XX
// handshake + secret-stream transport, and echoes back every decrypted message.
//
// The D dialer (vendored-free, our own port) connects, handshakes and expects its
// message echoed. A clean round-trip proves our secret-stream is wire-compatible.
//
// args: <portFile>
const net = require('net')
const fs = require('fs')
const SecretStream = require('@hyperswarm/secret-stream')

const [portFile] = process.argv.slice(2)

const server = net.createServer((rawSocket) => {
  const s = new SecretStream(false, rawSocket) // responder
  s.on('data', (data) => {
    console.log('JS-SS recv ' + data.length + ' bytes, echoing')
    s.write(data)
  })
  s.on('error', () => {})
})

server.listen(0, '127.0.0.1', () => {
  const port = server.address().port
  fs.writeFileSync(portFile, String(port))
  console.log('JS-SS LISTEN port=' + port)
})
