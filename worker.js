// ================= HELPER =================

async function hashPassword(password){
  const enc = new TextEncoder()
  const buffer = await crypto.subtle.digest("SHA-256", enc.encode(password))

  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}

function json(data){
  return new Response(JSON.stringify(data), {
    headers:{
      "Content-Type":"application/json",
      "Access-Control-Allow-Origin":"*"
    }
  })
}

// ================= MAIN =================

export default {
  async fetch(request, env) {

    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "*"
        }
      })
    }

    const url = new URL(request.url)

    // ================= REGISTER =================
    if (url.pathname === "/register" && request.method === "POST") {

      const { name, email, password } = await request.json()
      const cleanEmail = email.trim().toLowerCase()

      const exist = await env.DB.prepare(`
        SELECT email FROM users WHERE email=?
      `).bind(cleanEmail).first()

      if (exist) {
        return json({ error: "Email sudah terdaftar" })
      }

      const hash = await hashPassword(password)

      await env.DB.prepare(`
        INSERT INTO users (name,email,password)
        VALUES (?,?,?)
      `).bind(name, cleanEmail, hash).run()

      return json({
        token:"ok",
        user:{ name, email:cleanEmail }
      })
    }

    // ================= LOGIN =================
    if (url.pathname === "/login" && request.method === "POST") {

      const { email, password } = await request.json()
      const cleanEmail = email.trim().toLowerCase()

      const user = await env.DB.prepare(`
        SELECT * FROM users WHERE email=?
      `).bind(cleanEmail).first()

      if (!user) {
        return json({ error:"Email tidak ditemukan" })
      }

      const hash = await hashPassword(password)

      if (user.password !== hash) {
        return json({ error:"Password salah" })
      }

      return json({
        token:"ok",
        user:{
          email:user.email,
          name:user.name
        }
      })
    }

    return new Response("Not found", { status: 404 })
  }
}
