const DHT = require("hyperdht")
const crypto = require("crypto")
;(async () => {
  const pass = process.argv[2]
  const topic = crypto.createHash("sha256").update("photo-sync:"+pass).digest()
  const node = new DHT()
  await node.ready()
  console.log("JS lookup topic " + topic.toString("hex").slice(0,12) + " on live bootstrap")
  let found = 0
  const q = node.lookup(topic)
  const t = setTimeout(() => q.destroy(), 28000)
  try { for await (const r of q) { for (const p of (r.peers||[])) { found++; console.log("  JS found announcer " + p.publicKey.toString("hex").slice(0,16)) } } } catch(e){ console.log("lookup err", e.message) }
  clearTimeout(t)
  console.log("JS lookup done: found " + found + " announcer(s)")
  await node.destroy()
})()
