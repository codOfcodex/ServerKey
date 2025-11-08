// public/admin.js
async function api(path, token, opts) {
  const headers = { "Content-Type":"application/json" };
  if (token) headers["x-admin-token"] = token;
  const res = await fetch(path, Object.assign({ headers }, opts || {}));
  return res.json();
}

document.getElementById("load").addEventListener("click", async () => {
  const token = document.getElementById("token").value.trim();
  if (!token) return alert("Enter admin token");
  const data = await api("/admin/requests", token);
  if (data.status !== "ok") return alert("Error: " + (data.message || "unknown"));
  render(data.requests, data.issued, token);
});

function render(requests, issued, token) {
  const out = document.getElementById("content");
  out.innerHTML = "";

  const reqTitle = document.createElement("h3");
  reqTitle.textContent = "Requests";
  out.appendChild(reqTitle);

  if (!requests.length) {
    const p = document.createElement("div"); p.textContent = "No requests yet."; out.appendChild(p);
  }

  const table = document.createElement("table");
  const header = document.createElement("tr");
  header.innerHTML = "<th>ID</th><th>HWID</th><th>User</th><th>Note</th><th>Time</th><th>Status</th><th>Action</th>";
  table.appendChild(header);

  requests.slice().reverse().forEach(r => {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${r.id}</td><td><pre style='white-space:nowrap'>${r.hwid}</pre></td>
      <td>${r.username || r.userid || "-"}</td>
      <td>${r.note || "-"}</td>
      <td>${new Date(r.ts).toLocaleString()}</td>
      <td>${r.status}</td>
      <td></td>`;
    const act = document.createElement("td");
    const btn = document.createElement("button");
    btn.textContent = "Generate Key";
    btn.onclick = async () => {
      if (!confirm("Generate key for this HWID?")) return;
      const res = await api("/admin/generate", token, { method: "POST", body: JSON.stringify({ hwid: r.hwid, requestId: r.id })});
      if (res.status === "ok") {
        alert("Key generated:\n" + res.key + "\n\nGive this to the user.");
        // reload
        const reload = await api("/admin/requests", token);
        render(reload.requests, reload.issued, token);
      } else {
        alert("Error: " + (res.message || "unknown"));
      }
    };
    tr.lastElementChild.appendChild(btn);
    table.appendChild(tr);
  });

  out.appendChild(table);

  // Issued keys
  const title = document.createElement("h3"); title.textContent = "Issued Keys (revocable)"; out.appendChild(title);
  const pre = document.createElement("pre");
  pre.textContent = JSON.stringify(issued, null, 2);
  out.appendChild(pre);
}