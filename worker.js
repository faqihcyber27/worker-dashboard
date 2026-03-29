export default {
  async fetch(request, env) {
    const url = new URL(request.url)

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: cors(env) })
    }

    try {
      // PUBLIC
      if (url.pathname === "/api/register" && request.method === "POST")
        return register(request, env)

      if (url.pathname === "/api/login" && request.method === "POST")
        return login(request, env)

      // AUTH
      const user = await auth(request, env)

      if (url.pathname === "/api/vms" && request.method === "GET")
        return getVMs(request, env)

      if (url.pathname === "/api/vms" && request.method === "POST") {
        if (user.role !== "admin") return forbidden()
        return createVM(request, env)
      }

      if (url.pathname.startsWith("/api/vms/") && request.method === "PUT") {
        if (user.role !== "admin") return forbidden()
        return updateVM(request, env)
      }

      if (url.pathname.startsWith("/api/vms/") && request.method === "DELETE") {
        if (user.role !== "admin") return forbidden()
        return deleteVM(request, env)
      }

      return new Response("Not Found", { status: 404 })

    } catch (err) {
      return json({ error: err.message }, 500, env)
    }
  }
}

// ================= UTIL =================

function json(data, status = 200, env) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...cors(env)
    }
  })
}

function cors(env) {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "*",
    "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS"
  }
}

function forbidden() {
  return new Response(JSON.stringify({ error: "Forbidden" }), { status: 403 })
}

// ================= HASH =================

async function hashPassword(password) {
  const encoder = new TextEncoder()
  const data = encoder.encode(password)
  const hash = await crypto.subtle.digest("SHA-256", data)

  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("")
}

// ================= JWT =================

async function generateJWT(payload, env) {
  const secret = env.JWT_SECRET
  const encoder = new TextEncoder()

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  )

  const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }))
  const body = btoa(JSON.stringify(payload))

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(`${header}.${body}`)
  )

  const sig = btoa(String.fromCharCode(...new Uint8Array(signature)))

  return `${header}.${body}.${sig}`
}

async function verifyJWT(token, env) {
  const secret = env.JWT_SECRET
  const [header, body, signature] = token.split(".")

  const encoder = new TextEncoder()

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  )

  const valid = await crypto.subtle.verify(
    "HMAC",
    key,
    Uint8Array.from(atob(signature), c => c.charCodeAt(0)),
    encoder.encode(`${header}.${body}`)
  )

  if (!valid) throw new Error("Invalid token")

  const payload = JSON.parse(atob(body))

  if (payload.exp < Math.floor(Date.now() / 1000))
    throw new Error("Token expired")

  return payload
}

async function auth(request, env) {
  const authHeader = request.headers.get("Authorization")
  if (!authHeader) throw new Error("Unauthorized")

  const token = authHeader.split(" ")[1]
  return verifyJWT(token, env)
}

// ================= AUTH =================

async function register(request, env) {
  const { name, email, password } = await request.json()
  const hashed = await hashPassword(password)

  await env.DB.prepare(
    "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)"
  ).bind(name, email, hashed, "user").run()

  return json({ message: "Registered" }, 200, env)
}

async function login(request, env) {
  const { email, password } = await request.json()
  const hashed = await hashPassword(password)

  const user = await env.DB.prepare(
    "SELECT * FROM users WHERE email = ? AND password = ?"
  ).bind(email, hashed).first()

  if (!user) return json({ error: "Invalid login" }, 401, env)

  const token = await generateJWT({
    id: user.id,
    role: user.role,
    exp: Math.floor(Date.now() / 1000) + 3600
  }, env)

  return json({ token, role: user.role }, 200, env)
}

// ================= VM =================

async function getVMs(request, env) {
  const url = new URL(request.url)
  const q = url.searchParams.get("q") || ""

  const data = await env.DB.prepare(`
    SELECT * FROM vms 
    WHERE name LIKE ? OR ip LIKE ?
    ORDER BY id DESC
  `).bind(`%${q}%`, `%${q}%`).all()

  return json(data.results, 200, env)
}

async function createVM(request, env) {
  const vm = await request.json()

  await env.DB.prepare(`
    INSERT INTO vms 
    (name, ip, function, cluster, host, cpu, memory, disk, os, vlan, environment)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    vm.name,
    vm.ip,
    vm.function,
    vm.cluster,
    vm.host,
    vm.cpu,
    vm.memory,
    vm.disk,
    vm.os,
    vm.vlan,
    vm.environment
  ).run()

  return json({ message: "VM created" }, 200, env)
}

async function updateVM(request, env) {
  const id = request.url.split("/").pop()
  const vm = await request.json()

  await env.DB.prepare(`
    UPDATE vms SET 
    name=?, ip=?, function=?, cluster=?, host=?, cpu=?, memory=?, disk=?, os=?, vlan=?, environment=?
    WHERE id=?
  `).bind(
    vm.name,
    vm.ip,
    vm.function,
    vm.cluster,
    vm.host,
    vm.cpu,
    vm.memory,
    vm.disk,
    vm.os,
    vm.vlan,
    vm.environment,
    id
  ).run()

  return json({ message: "Updated" }, 200, env)
}

async function deleteVM(request, env) {
  const id = request.url.split("/").pop()

  await env.DB.prepare("DELETE FROM vms WHERE id=?")
    .bind(id).run()

  return json({ message: "Deleted" }, 200, env)
}
