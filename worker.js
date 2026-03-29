export default {
  async fetch(request, env) {
    const url = new URL(request.url)

    // CORS
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders() })
    }

    try {
      // ROUTING
      if (url.pathname === "/api/register" && request.method === "POST") {
        return register(request, env)
      }

      if (url.pathname === "/api/login" && request.method === "POST") {
        return login(request, env)
      }

      if (url.pathname === "/api/vms" && request.method === "GET") {
        return getVMs(env)
      }

      if (url.pathname === "/api/vms" && request.method === "POST") {
        return createVM(request, env)
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
      ...corsHeaders()
    }
  })
}

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "*",
    "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS"
  }
}

// ================= AUTH =================

async function register(request, env) {
  const body = await request.json()

  const { name, email, password } = body

  await env.DB.prepare(
    "INSERT INTO users (name, email, password) VALUES (?, ?, ?)"
  ).bind(name, email, password).run()

  return json({ message: "User created" })
}

async function login(request, env) {
  const { email, password } = await request.json()

  const user = await env.DB.prepare(
    "SELECT * FROM users WHERE email = ? AND password = ?"
  ).bind(email, password).first()

  if (!user) {
    return json({ error: "Invalid credentials" }, 401)
  }

  return json({
    message: "Login success",
    user: {
      id: user.id,
      role: user.role
    }
  })
}

// ================= VM =================

async function getVMs(env) {
  const data = await env.DB.prepare("SELECT * FROM vms").all()
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
