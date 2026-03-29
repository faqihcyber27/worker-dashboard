export default {
  async fetch(request, env) {
    const url = new URL(request.url)

    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: cors() })
    }

    try {
      // ================= PUBLIC =================
      if (url.pathname === "/api/register" && request.method === "POST") {
        return register(request, env)
      }

      if (url.pathname === "/api/login" && request.method === "POST") {
        return login(request, env)
      }

      // ================= PROTECTED =================
      let user
      try {
        user = await auth(request, env)
      } catch (err) {
        return json({ error: "Unauthorized" }, 401)
      }

      if (url.pathname === "/api/vms" && request.method === "GET") {
        return getVMs(request, env)
      }

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
      return json({ error: err.message }, 500)
    }
  }
}

// ================= UTIL =================

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...cors()
    }
  })
}

function cors() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS"
  }
}

function forbidden() {
  return json({ error: "Forbidden" }, 403)
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

  if (!header || !body || !signature) {
    throw new Error("Invalid token format")
  }

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

  if (payload.exp < Math.floor(Date.now() / 1000)) {
    throw new Error("Token expired")
  }

  return payload
}

async function auth(request, env) {
  const authHeader = request.headers.get("Authorization")

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    throw new Error("Unauthorized")
  }

  const token = authHeader.split(" ")[1]
  return verifyJWT(token, env)
}

// ================= AUTH =================

async function register(request, env) {
  const { name, email, password } = await request.json()

  if (!name || !email || !password) {
    return json({ error: "Missing fields" }, 400)
  }

  const hashed = await hashPassword(password)

  try {
    await env.DB.prepare(
      "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)"
    ).bind(name, email, hashed, "user").run()

    return json({ message: "Registered" })

  } catch {
    return json({ error: "Email already exists" }, 400)
  }
}

async function login(request, env) {
  const { email, password } = await request.json()

  if (!email || !password) {
    return json({ error: "Missing credentials" }, 400)
  }

  const hashed = await hashPassword(password)

  const user = await env.DB.prepare(
    "SELECT * FROM users WHERE email = ? AND password = ?"
  ).bind(email, hashed).first()

  if (!user) {
    return json({ error: "Invalid login" }, 401)
  }

  const token = await generateJWT({
    id: user.id,
    role: user.role,
    exp: Math.floor(Date.now() / 1000) + 3600
  }, env)

  return json({ token, role: user.role })
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

  return json(data.results)
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

  return json({ message: "VM created" })
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

  return json({ message: "Updated" })
}

async function deleteVM(request, env) {
  const id = request.url.split("/").pop()

  await env.DB.prepare("DELETE FROM vms WHERE id=?")
    .bind(id).run()

  return json({ message: "Deleted" })
}
