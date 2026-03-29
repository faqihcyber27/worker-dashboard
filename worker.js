export default {
  async fetch(request, env){

    if(request.method === "OPTIONS"){
      return new Response(null,{
        headers:{
          "Access-Control-Allow-Origin":"*",
          "Access-Control-Allow-Headers":"*",
          "Access-Control-Allow-Methods":"GET,POST,PUT,DELETE,OPTIONS"
        }
      })
    }

    const url = new URL(request.url)

    try{

      // ================= PUBLIC =================

      if(url.pathname === "/login" && request.method === "POST"){
        const { email, password } = await request.json()

        const user = await env.DB.prepare(
          "SELECT * FROM users WHERE email=?"
        ).bind(email.trim().toLowerCase()).first()

        if(!user){
          return json({error:"Email tidak ditemukan"},401)
        }

        const hash = await hashPassword(password)

        if(user.password !== hash){
          return json({error:"Password salah"},401)
        }

        return json({
          token:"ok",
          role:user.role,
          user:{
            name: user.name,
            email: user.email,
            role: user.role
          }
        })
      }

      if(url.pathname === "/register" && request.method === "POST"){
        const { name,email,password } = await request.json()

        const hash = await hashPassword(password)

        await env.DB.prepare(
          "INSERT INTO users (name,email,password,role) VALUES (?,?,?,?)"
        ).bind(
          name,
          email.trim().toLowerCase(),
          hash,
          "user"
        ).run()

        return json({message:"ok"})
      }

      // ================= VM =================

      // GET (boleh semua)
      if(url.pathname === "/vms" && request.method === "GET"){
        const data = await env.DB.prepare(
          "SELECT * FROM vms ORDER BY id DESC"
        ).all()

        return json(
          (data.results||[]).map(v=>({
            ...v,
            disk: v.disk ? JSON.parse(v.disk) : []
          }))
        )
      }

      // 🔒 ambil role dari header
      const role = request.headers.get("role") || "user"

      // 🔒 PROTECT (hanya admin)
      if(role !== "admin"){
        return json({error:"Forbidden"},403)
      }

      // CREATE
      if(url.pathname === "/vms" && request.method === "POST"){
        const vm = await request.json()

        await env.DB.prepare(`
          INSERT INTO vms 
          (name, ip, function, cluster, host, cpu, memory, os, vlan, storage, disk, environment, platform)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          vm.name||"",
          vm.ip||"",
          vm.function||"",
          vm.cluster||"",
          vm.host||"",
          vm.cpu||"",
          vm.memory||"",
          vm.os||"",
          vm.vlan||"",
          vm.storage||"",
          JSON.stringify(vm.disk||[]),
          vm.environment||"",
          vm.platform||""
        ).run()

        return json({msg:"created"})
      }

      // UPDATE
      if(url.pathname.startsWith("/vms/") && request.method === "PUT"){
        const id = url.pathname.split("/").pop()
        const vm = await request.json()

        await env.DB.prepare(`
          UPDATE vms SET 
          name=?, ip=?, function=?, cluster=?, host=?, cpu=?, memory=?, os=?, vlan=?, storage=?, disk=?, environment=?, platform=?
          WHERE id=?
        `).bind(
          vm.name||"",
          vm.ip||"",
          vm.function||"",
          vm.cluster||"",
          vm.host||"",
          vm.cpu||"",
          vm.memory||"",
          vm.os||"",
          vm.vlan||"",
          vm.storage||"",
          JSON.stringify(vm.disk||[]),
          vm.environment||"",
          vm.platform||"",
          id
        ).run()

        return json({msg:"updated"})
      }
      
      // BULK INSERT
if(url.pathname === "/vms/bulk" && request.method === "POST"){

  const role = request.headers.get("role") || "user"
  if(role !== "admin"){
    return json({error:"Forbidden"},403)
  }

  const data = await request.json()

  const stmt = env.DB.prepare(`
    INSERT INTO vms 
    (name, ip, function, cluster, host, cpu, memory, os, vlan, storage, disk, environment, platform)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `)

  const batch = data.map(vm =>
    stmt.bind(
      vm.name||"",
      vm.ip||"",
      vm.function||"",
      vm.cluster||"",
      vm.host||"",
      vm.cpu||"",
      vm.memory||"",
      vm.os||"",
      vm.vlan||"",
      vm.storage||"",
      JSON.stringify(vm.disk||[]),
      vm.environment||"",
      vm.platform||""
    )
  )

  await env.DB.batch(batch)

  return json({msg:"bulk insert success"})
}

      // DELETE
      if(url.pathname.startsWith("/vms/") && request.method === "DELETE"){
        const id = url.pathname.split("/").pop()

        await env.DB.prepare(
          "DELETE FROM vms WHERE id=?"
        ).bind(id).run()

        return json({msg:"deleted"})
      }

      return new Response("Not found",{status:404})

    }catch(err){
      return json({error:err.message},500)
    }
  }
}

// ================= HELPER =================

async function hashPassword(password){
  const enc = new TextEncoder()
  const buffer = await crypto.subtle.digest("SHA-256", enc.encode(password))
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2,'0'))
    .join('')
}

function json(data,status=200){
  return new Response(JSON.stringify(data),{
    status,
    headers:{
      "Content-Type":"application/json",
      "Access-Control-Allow-Origin":"*"
    }
  })
}
