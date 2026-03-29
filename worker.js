// ================= HELPER =================

async function hashPassword(password){
  const enc = new TextEncoder()
  const buffer = await crypto.subtle.digest("SHA-256", enc.encode(password))
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}

function json(data, status = 200){
  return new Response(JSON.stringify(data), {
    status,
    headers:{
      "Content-Type":"application/json",
      "Access-Control-Allow-Origin":"*",
      "Access-Control-Allow-Headers":"*",
      "Access-Control-Allow-Methods":"GET,POST,PUT,DELETE,OPTIONS"
    }
  })
}

function cors(){
  return {
    "Access-Control-Allow-Origin":"*",
    "Access-Control-Allow-Headers":"*",
    "Access-Control-Allow-Methods":"GET,POST,PUT,DELETE,OPTIONS"
  }
}

// ================= MAIN =================

export default {
  async fetch(request, env){

    if(request.method === "OPTIONS"){
      return new Response(null,{headers:cors()})
    }

    const url = new URL(request.url)

    try{

      // ================= GET VM =================
      if(url.pathname === "/vms" && request.method === "GET"){
        const data = await env.DB.prepare(
          "SELECT * FROM vms ORDER BY id DESC"
        ).all()

        const result = (data.results || []).map(vm => ({
          ...vm,
          disk: vm.disk ? JSON.parse(vm.disk) : []
        }))

        return json(result)
      }

      // ================= CREATE =================
      if(url.pathname === "/vms" && request.method === "POST"){
        const vm = await request.json()

        await env.DB.prepare(`
          INSERT INTO vms 
          (name, ip, function, cluster, host, cpu, memory, os, vlan, storage, disk, environment, platform)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          vm.name || "",
          vm.ip || "",
          vm.function || "",
          vm.cluster || "",
          vm.host || "",
          vm.cpu || "",
          vm.memory || "",
          vm.os || "",
          vm.vlan || "",
          vm.storage || "",
          JSON.stringify(vm.disk || []),
          vm.environment || "",
          vm.platform || ""
        ).run()

        return json({message:"Created"})
      }

      // ================= UPDATE =================
      if(url.pathname.startsWith("/vms/") && request.method === "PUT"){
        const id = url.pathname.split("/").pop()
        const vm = await request.json()

        await env.DB.prepare(`
          UPDATE vms SET 
          name=?, ip=?, function=?, cluster=?, host=?, cpu=?, memory=?, os=?, vlan=?, storage=?, disk=?, environment=?, platform=?
          WHERE id=?
        `).bind(
          vm.name || "",
          vm.ip || "",
          vm.function || "",
          vm.cluster || "",
          vm.host || "",
          vm.cpu || "",
          vm.memory || "",
          vm.os || "",
          vm.vlan || "",
          vm.storage || "",
          JSON.stringify(vm.disk || []),
          vm.environment || "",
          vm.platform || "",
          id
        ).run()

        return json({message:"Updated"})
      }

      // ================= DELETE =================
      if(url.pathname.startsWith("/vms/") && request.method === "DELETE"){
        const id = url.pathname.split("/").pop()

        await env.DB.prepare(
          "DELETE FROM vms WHERE id=?"
        ).bind(id).run()

        return json({message:"Deleted"})
      }

      return new Response("Not found",{status:404})

    }catch(err){
      return json({error:err.message},500)
    }
  }
}
