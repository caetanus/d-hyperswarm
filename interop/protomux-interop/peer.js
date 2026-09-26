// The JS side of the protomux wire test: stdin/stdout carry frames (u32be length + bytes),
// one frame per protomux message — the same boundaries a secret-stream keeps.
const path = require('path')
const nm = path.join(__dirname, '..', 'hyperdht-js-peer', 'node_modules')
const Protomux = require(path.join(nm, 'protomux'))
const c = require(path.join(__dirname, '..', 'hyperswarm-js-peer', 'node_modules', 'compact-encoding'))
const { Duplex } = require('stream')

let inbuf = Buffer.alloc(0)
const stream = new Duplex({
  objectMode: true,
  read () {},
  write (chunk, enc, cb) {
    const h = Buffer.alloc(4); h.writeUInt32BE(chunk.length)
    process.stdout.write(Buffer.concat([h, chunk])); cb()
  }
})
stream.userData = null
process.stdin.on('data', (d) => {
  inbuf = Buffer.concat([inbuf, d])
  while (inbuf.length >= 4) {
    const n = inbuf.readUInt32BE(0)
    if (inbuf.length < 4 + n) break
    stream.push(inbuf.subarray(4, 4 + n)); inbuf = inbuf.subarray(4 + n)
  }
})
process.stdin.on('end', () => process.exit(0))

const mux = new Protomux(stream)
const log = (...a) => process.stderr.write('js: ' + a.join(' ') + '\n')

// accept "echo" channels: reply "js:" + each string, with a handshake
mux.pair({ protocol: 'echo' }, () => {
  const ch = mux.createChannel({
    protocol: 'echo',
    handshake: c.string,
    onopen (hs) { log('opened, handshake', JSON.stringify(hs)) },
    onclose (remote) { log('closed, remote=' + remote) }
  })
  const m = ch.addMessage({ encoding: c.string, onmessage (v) { log('got', v); m.send('js:' + v) } })
  ch.open('hello-from-js')
})
// and open one of our own with a uint message, to test the other direction
const up = mux.createChannel({ protocol: 'counter', id: Buffer.from('ab', 'hex'), onopen () { log('counter opened') } })
const um = up.addMessage({ encoding: c.uint, onmessage (v) { log('counter reply', v); if (v >= 4) up.close(); else um.send(v + 1) } })
up.open()
um.send(1)
