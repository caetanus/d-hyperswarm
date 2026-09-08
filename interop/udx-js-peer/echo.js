// A UDX echo peer built on the REAL udx-native (holepunch). It binds a socket,
// publishes its port, waits for the dialer's port (file rendezvous — avoids fixed
// ports), connects a stream to the dialer and echoes back whatever it receives.
//
// This is the reference side of the phase-2 acceptance: if a D peer driving the
// vendored libudx through our vibe facade can round-trip a reliable stream with
// this, our UDX is wire-compatible with the real thing.
//
// args: <ownId> <peerId> <ownPortFile> <peerPortFile>
const UDX = require('udx-native')
const fs = require('fs')

const [ownId, peerId, ownPortFile, peerPortFile] = process.argv.slice(2)

const u = new UDX()
const socket = u.createSocket()
socket.bind(0, '127.0.0.1')

const ownPort = socket.address().port
fs.writeFileSync(ownPortFile, String(ownPort))
console.log('JS LISTEN port=' + ownPort + ' id=' + ownId)

function waitForPeer () {
  let peerPort = 0
  try {
    const s = fs.readFileSync(peerPortFile, 'utf8').trim()
    if (s) peerPort = Number(s)
  } catch (_) {}

  if (!peerPort) { setTimeout(waitForPeer, 20); return }

  const stream = u.createStream(Number(ownId))
  stream.connect(socket, Number(peerId), peerPort, '127.0.0.1')
  stream.on('data', function (data) {
    console.log('JS recv ' + data.length + ' bytes, echoing')
    stream.write(data) // echo straight back
  })
  stream.on('error', function () {})
  console.log('JS connected to peer port=' + peerPort)
}

waitForPeer()

// Stay alive; the harness kills this process when the dialer is done.
setInterval(() => {}, 1 << 30)
