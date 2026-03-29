export default {
  async fetch(request, env) {
    const url = new URL(request.url)

    // CORS
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: cors() })
    }

    try {

      // ================= TEST =================
      if (url.pathname === "/test") {
        return new Response("WORKER OK")
      }

      // ================= REGISTER =================
      if (url.pathname === "/api/register" && request.method === "POST") {
        return register(request, env)
      }

      // ================= LOGIN =================
      if (url.pathname === "/api/login" && request.method === "POST") {
        return login(request, env)
      }

      // ================= PROTECTED =================
      if (url.pathname === "/api/me") {
        return me(request, env)
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
    "Access-Control-Allow-Headers": "*",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
  }
}

// ================= REGISTER =================

async function register(request, env) {
  const { name, email, password } = await request.json()

  if (!name || !email || !password) {
    return json({ error: "Isi semua field" }, 400)
  }

  const cleanEmail = email.trim().toLowerCase()
  const cleanPassword = password.trim()

  try {
    await env.DB.prepare(
      "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)"
    ).bind(name, cleanEmail, cleanPassword, "user").run()

    return json({ message: "Register berhasil" })

  } catch {
    return json({ error: "Email sudah ada" }, 400)
  }
}

// ================= LOGIN =================

async function login(request, env) {
  const { email, password } = await request.json()

  const cleanEmail = email.trim().toLowerCase()
  const cleanPassword = password.trim()

  const user = await env.DB.prepare(
    "SELECT * FROM users WHERE email = ?"
  ).bind(cleanEmail).first()

  if (!user) {
    return json({ error: "User tidak ditemukan" }, 404)
  }

  if (user.password !== cleanPassword) {
    return json({ error: "Password salah" }, 401)
  }

  // token simple
  const token = btoa(cleanEmail + ":" + Date.now())

  await env.DB.prepare(
    "UPDATE users SET token = ? WHERE id = ?"
  ).bind(token, user.id).run()

  return json({
    message: "Login berhasil",
    token,
    role: user.role
  })
}

// ================= AUTH =================

async function me(request, env) {
  const authHeader = request.headers.get("Authorization")

  if (!authHeader) {
    return json({ error: "Unauthorized" }, 401)
  }

  const token = authHeader.split(" ")[1]

  const user = await env.DB.prepare(
    "SELECT * FROM users WHERE token = ?"
  ).bind(token).first()

  if (!user) {
    return json({ error: "Invalid token" }, 401)
  }

  return json({
    email: user.email,
    name: user.name,
    role: user.role
  })
}
