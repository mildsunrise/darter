#!/usr/bin/env node

// Node.js script that runs whatever command was given (usually pub)
// making traffic go through a MITM proxy that will intercept HTTPS
// requests to pub.dartlang.org and pub.dev. When a package is queried,
// the proxy will only return versions that existed at the given time.
//
// This is useful to simulate a `pub get` in the past. Remove
// `pubspec.lock` first, then run i.e.:
//
//      path/to/timemachine_pub.js 2019-10-14 flutter pub get
//
// Before using this, you'll need to add the fake CA (files/ca.crt)
// to the system's (OpenSSL) trust store.

const { promisify } = require('util')
const { once } = require('events')
const stream = require('stream')
const pipeline = promisify(stream.pipeline)

const { join } = require('path')
const { readFileSync } = require('fs')
const net = require('net')
const http = require('http')
const https = require('https')
const { spawn } = require('child_process')

const args = process.argv.slice(2)
if (args.length < 2) {
  console.error(`Usage: ${process.argv[1]} <DATE> command...`)
  process.exit(1)
}
const DATE = new Date(args[0])
const COMMAND = args.slice(1)


const agent = new https.Agent({ keepAlive: true })
const upstreamOptions = { agent }

const fakeServer = https.createServer({
  key: readFileSync(join(__dirname, 'files', 'timemachine.key')),
  cert: readFileSync(join(__dirname, 'files', 'timemachine.crt')),
}, async (req, res) => {
  let { url: path, headers, method } = req
  headers = { ...headers }
  delete headers.connection // connection-level headers must be removed
  delete headers.host // let Node.js populate it for us
  delete headers['accept-encoding'] // I'm too lazy to handle this correctly

  const oreq = https.request({ ...upstreamOptions, hostname: 'pub.dev', path, headers, method })
  await pipeline(req, oreq)

  let ores
  try {
    ; [ores] = await once(oreq, 'response')
  } catch (e) {
    console.error(`[timemachine] Upstream request error: ${e}`)
    oreq.destroy()
    req.destroy()
    return
  }

  res.statusCode = ores.statusCode
  Object.keys(ores.headers).forEach(k => res.setHeader(k, ores.headers[k]))
  res.removeHeader('content-length') // let Node.js populate it for us

  if (method === 'GET' && path.startsWith('/api/packages/') && res.statusCode === 200) {
    const body = await collectBody(ores)
    let data = JSON.parse(body.toString())
    data.versions = data.versions.filter(v => new Date(v.published) < DATE)
    data.latest = data.versions[data.versions.length - 1]
    return res.end(Buffer.from(JSON.stringify(data)))
  }

  res.setHeader('content-length', ores.headers['content-length'])
  await pipeline(ores, res)
})

const httpsProxy = http.createServer((req, res) => {
  res.statusCode = 405
  return res.end('This is an HTTPS proxy, only CONNECT allowed\n')
}).on('connect', (req, socket, head) => {
  socket.unshift(head)
  const { port, hostname } = new URL(`http://${req.url.toLowerCase()}`)

  if (['pub.dartlang.org', 'pub.dev'].includes(hostname) && port === '443') {
    socket.write('HTTP/1.1 200 Connection Established\r\n\r\n')
    return fakeServer.emit('connection', socket)
  }

  // console.log(`[timemachine] Connection request for ${req.url}; proxying through`)
  const upstream = net.connect(Number(port) || 80, hostname)
  once(upstream, 'connect').then(() => {
    socket.write('HTTP/1.1 200 Connection Established\r\n\r\n')
    pipeline(upstream, socket).catch(() => {})
    pipeline(socket, upstream).catch(() => {})
  }, error => {
    socket.end(`HTTP/1.1 502 Proxy Connection Failed\r\n\r\n${error}\n`)
  })
})

httpsProxy.unref()
httpsProxy.listen(() => {
  console.log(`[timemachine] Ready, simulating ${DATE}`)
  const proxyUrl = `http://localhost:${httpsProxy.address().port}`
  const newEnv = { ...process.env, https_proxy: proxyUrl }
  const child = spawn(COMMAND[0], COMMAND.slice(1), { stdio: 'inherit', env: newEnv })
  child.on('error', error => {
    console.log(`[timemachine] exec failed: ${error.message}`)
    process.exit(255)
  })
  child.on('exit', (code, signal) => {
    if (signal) {
      console.log(`[timemachine] child died from signal ${signal}`)
      process.exit(255)
    }
    process.exit(code)
  })
})


// utils

function collectBody(stream) {
  const chunks = []
  stream.on('data', chunk => chunks.push(chunk))
  return once(stream, 'end').then(() => Buffer.concat(chunks))
}
