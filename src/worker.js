const SESSION_DAYS = 7;
const encoder = new TextEncoder();

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers }
  });
}
function fail(message, status = 400) { return json({ error: message }, status); }
function id() { return crypto.randomUUID(); }
function b64url(bytes) {
  let s = "";
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
async function sha256(text) {
  const buf = await crypto.subtle.digest("SHA-256", encoder.encode(text));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}
async function passwordHash(password, salt = crypto.getRandomValues(new Uint8Array(16))) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 310000, hash: "SHA-256" }, key, 256);
  return `${b64url(salt)}.${b64url(bits)}`;
}
function fromB64url(s) {
  s = s.replaceAll("-", "+").replaceAll("_", "/");
  while (s.length % 4) s += "=";
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}
async function verifyPassword(password, stored) {
  const [saltStr, expected] = (stored || "").split(".");
  if (!saltStr || !expected) return false;
  const salt = fromB64url(saltStr);
  const got = await passwordHash(password, salt);
  return constantTimeEqual(got.split(".")[1], expected);
}
function constantTimeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let v = 0;
  for (let i = 0; i < a.length; i++) v |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return v === 0;
}
function cookie(name, value, maxAge) {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}
function clearCookie() { return "warranty_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"; }
function getCookie(request, name) {
  const raw = request.headers.get("Cookie") || "";
  const part = raw.split(";").map(x => x.trim()).find(x => x.startsWith(name + "="));
  return part ? part.slice(name.length + 1) : null;
}
async function bodyJson(request, max = 1_000_000) {
  const len = Number(request.headers.get("content-length") || 0);
  if (len > max) throw new Error("حجم الطلب أكبر من المسموح.");
  return await request.json();
}
function normalizeCode(v) {
  return String(v ?? "").trim().toUpperCase().replace(/\s+/g, "");
}
async function audit(env, userId, action, detail = "") {
  await env.DB.prepare("INSERT INTO audit_log (id, actor_user_id, action, detail) VALUES (?, ?, ?, ?)")
    .bind(id(), userId || null, action, String(detail).slice(0, 200)).run();
}
async function currentUser(request, env) {
  const token = getCookie(request, "warranty_session");
  if (!token) return null;
  const tokenHash = await sha256(token);
  const row = await env.DB.prepare(
    `SELECT u.id, u.username, u.display_name, u.role, u.active
     FROM sessions s JOIN users u ON u.id=s.user_id
     WHERE s.token_hash=? AND s.expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now')`
  ).bind(tokenHash).first();
  if (!row || !row.active) return null;
  return row;
}
function roleAtLeast(user, roles) { return !!user && roles.includes(user.role); }
async function requireUser(request, env, roles = ["owner","admin","viewer"]) {
  const user = await currentUser(request, env);
  if (!user) return { error: fail("يلزم تسجيل الدخول.", 401) };
  if (!roleAtLeast(user, roles)) return { error: fail("ليست لديك صلاحية لتنفيذ هذا الإجراء.", 403) };
  return { user };
}
function sameOrigin(request) {
  const origin = request.headers.get("Origin");
  if (!origin) return true; // non-browser clients may omit Origin; cookie remains SameSite=Strict
  return origin === new URL(request.url).origin;
}

async function api(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  if (!sameOrigin(request) && request.method !== "GET") return fail("طلب غير مسموح.", 403);

  if (path === "/api/status" && request.method === "GET") {
    const row = await env.DB.prepare("SELECT COUNT(*) AS n FROM users").first();
    return json({ initialized: Number(row.n) > 0 });
  }

  if (path === "/api/setup" && request.method === "POST") {
    if (!env.SETUP_TOKEN) return fail("إعداد التهيئة غير متاح. اضبط SETUP_TOKEN في Cloudflare.", 503);
    let b; try { b = await bodyJson(request, 10000); } catch { return fail("بيانات غير صحيحة."); }
    const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM users").first();
    if (Number(count.n) > 0) return fail("تم إعداد النظام بالفعل.", 409);
    if (!constantTimeEqual(String(b.setupToken || ""), env.SETUP_TOKEN)) return fail("رمز التهيئة غير صحيح.", 403);
    const username = String(b.username || "").trim();
    const displayName = String(b.displayName || "").trim();
    const password = String(b.password || "");
    if (!/^[a-zA-Z0-9._-]{3,40}$/.test(username)) return fail("اسم المستخدم يجب أن يكون 3–40 حرفًا إنجليزيًا أو رقمًا أو . _ -.");
    if (displayName.length < 2 || displayName.length > 80) return fail("اكتب اسمًا صحيحًا.");
    if (password.length < 14 || password.length > 200) return fail("كلمة المرور يجب أن تكون 14 حرفًا على الأقل.");
    await env.DB.prepare("INSERT INTO users (id, username, display_name, password_hash, role) VALUES (?, ?, ?, ?, 'owner')")
      .bind(id(), username, displayName, await passwordHash(password)).run();
    await audit(env, null, "setup_owner", username);
    return json({ ok: true });
  }

  if (path === "/api/login" && request.method === "POST") {
    let b; try { b = await bodyJson(request, 10000); } catch { return fail("بيانات غير صحيحة."); }
    const username = String(b.username || "").trim();
    const password = String(b.password || "");
    const user = await env.DB.prepare("SELECT * FROM users WHERE username=? COLLATE NOCASE AND active=1").bind(username).first();
    // Perform a password derivation even when username does not exist, reducing timing differences.
    const valid = user ? await verifyPassword(password, user.password_hash) : await verifyPassword(password, "AAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    if (!user || !valid) return fail("اسم المستخدم أو كلمة المرور غير صحيحة.", 401);
    const token = b64url(crypto.getRandomValues(new Uint8Array(32)));
    const tokenHash = await sha256(token);
    await env.DB.prepare("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now', ?))")
      .bind(tokenHash, user.id, `+${SESSION_DAYS} days`).run();
    await audit(env, user.id, "login", "");
    return json({ ok: true, user: { username: user.username, displayName: user.display_name, role: user.role } }, 200,
      { "set-cookie": cookie("warranty_session", token, SESSION_DAYS * 86400) });
  }

  if (path === "/api/logout" && request.method === "POST") {
    const token = getCookie(request, "warranty_session");
    if (token) await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await sha256(token)).run();
    return json({ ok: true }, 200, { "set-cookie": clearCookie() });
  }

  if (path === "/api/me" && request.method === "GET") {
    const user = await currentUser(request, env);
    return user ? json({ user: { username: user.username, displayName: user.display_name, role: user.role } }) : fail("غير مسجل الدخول.", 401);
  }

  if (path === "/api/activate" && request.method === "POST") {
    let b; try { b = await bodyJson(request, 10000); } catch { return fail("بيانات غير صحيحة."); }
    const code = normalizeCode(b.code);
    if (code.length < 8 || code.length > 128) return fail("كود الضمان غير صحيح أو غير موجود.");
    const codeHash = await sha256(code);
    // Conditional update is atomic: only one concurrent request can transition unused -> activated.
    const result = await env.DB.prepare(
      "UPDATE warranty_codes SET status='activated' WHERE code_hash=? AND status='unused'"
    ).bind(codeHash).run();
    if (result.meta.changes === 1) {
      await env.DB.prepare("INSERT INTO activations (id, code_hash) VALUES (?, ?)").bind(id(), codeHash).run();
      return json({ ok: true, message: "تم تفعيل الضمان بنجاح." });
    }
    const exists = await env.DB.prepare("SELECT status FROM warranty_codes WHERE code_hash=?").bind(codeHash).first();
    if (exists?.status === "activated") return fail("هذا الكود تم تفعيله من قبل.", 409);
    return fail("الكود غير صحيح أو غير موجود.", 404);
  }

  if (path === "/api/dashboard" && request.method === "GET") {
    const auth = await requireUser(request, env);
    if (auth.error) return auth.error;
    const [total, unused, activated] = await Promise.all([
      env.DB.prepare("SELECT COUNT(*) n FROM warranty_codes").first(),
      env.DB.prepare("SELECT COUNT(*) n FROM warranty_codes WHERE status='unused'").first(),
      env.DB.prepare("SELECT COUNT(*) n FROM warranty_codes WHERE status='activated'").first()
    ]);
    return json({ total: total.n, unused: unused.n, activated: activated.n, user: {
      username: auth.user.username, displayName: auth.user.display_name, role: auth.user.role
    }});
  }

  if (path === "/api/activations" && request.method === "GET") {
    const auth = await requireUser(request, env);
    if (auth.error) return auth.error;
    const limit = Math.min(500, Math.max(1, Number(url.searchParams.get("limit") || 200)));
    const rows = await env.DB.prepare(
      `SELECT a.activated_at, substr(a.code_hash,1,12) AS code_reference
       FROM activations a ORDER BY a.activated_at DESC LIMIT ?`
    ).bind(limit).all();
    return json({ rows: rows.results || [] });
  }

  if (path === "/api/codes" && request.method === "GET") {
    const auth = await requireUser(request, env);
    if (auth.error) return auth.error;
    const status = url.searchParams.get("status");
    const q = String(url.searchParams.get("q") || "").trim().slice(0, 100);
    const limit = Math.min(500, Math.max(1, Number(url.searchParams.get("limit") || 200)));
    let where = "1=1", binds = [];
    if (status === "unused" || status === "activated") { where += " AND c.status=?"; binds.push(status); }
    if (q) { where += " AND substr(c.code_hash,1,12)=?"; binds.push(q); }
    binds.push(limit);
    const rows = await env.DB.prepare(
      `SELECT substr(c.code_hash,1,12) AS code_reference, c.status, c.imported_at, a.activated_at
       FROM warranty_codes c LEFT JOIN activations a ON a.code_hash=c.code_hash
       WHERE ${where} ORDER BY COALESCE(a.activated_at,c.imported_at) DESC LIMIT ?`
    ).bind(...binds).all();
    return json({ rows: rows.results || [] });
  }

  if (path === "/api/import" && request.method === "POST") {
    const auth = await requireUser(request, env, ["owner","admin"]);
    if (auth.error) return auth.error;
    let b; try { b = await bodyJson(request, 5_000_000); } catch { return fail("تعذر قراءة الملف أو حجمه أكبر من المسموح."); }
    if (!Array.isArray(b.codes) || b.codes.length < 1 || b.codes.length > 20000) return fail("عدد الأكواد يجب أن يكون بين 1 و20,000 في الدفعة الواحدة.");
    const unique = new Set();
    const codes = [];
    for (const raw of b.codes) {
      const code = normalizeCode(raw);
      if (!code) continue;
      if (code.length < 8 || code.length > 128) return fail("يوجد كود أقصر من 8 أحرف أو أطول من 128 حرفًا.");
      if (!unique.has(code)) { unique.add(code); codes.push(code); }
    }
    let inserted = 0;
    // Batch in chunks to stay within D1 batch limits.
    for (let i = 0; i < codes.length; i += 100) {
      const statements = codes.slice(i, i + 100).map(async code => ({
        hash: await sha256(code)
      }));
      const hashed = await Promise.all(statements);
      const stmts = hashed.map(x => env.DB.prepare(
        "INSERT OR IGNORE INTO warranty_codes (code_hash, imported_by) VALUES (?, ?)"
      ).bind(x.hash, auth.user.id));
      const result = await env.DB.batch(stmts);
      inserted += result.reduce((sum, r) => sum + (r.meta?.changes || 0), 0);
    }
    await audit(env, auth.user.id, "import_codes", `received=${b.codes.length}; unique=${codes.length}; inserted=${inserted}`);
    return json({ ok: true, received: b.codes.length, unique: codes.length, inserted, skipped: b.codes.length - inserted });
  }

  if (path === "/api/users" && request.method === "GET") {
    const auth = await requireUser(request, env, ["owner"]);
    if (auth.error) return auth.error;
    const rows = await env.DB.prepare("SELECT id, username, display_name, role, active, created_at FROM users ORDER BY created_at").all();
    return json({ rows: rows.results || [] });
  }

  if (path === "/api/users" && request.method === "POST") {
    const auth = await requireUser(request, env, ["owner"]);
    if (auth.error) return auth.error;
    let b; try { b = await bodyJson(request, 10000); } catch { return fail("بيانات غير صحيحة."); }
    const username = String(b.username || "").trim();
    const displayName = String(b.displayName || "").trim();
    const password = String(b.password || "");
    const role = String(b.role || "");
    if (!/^[a-zA-Z0-9._-]{3,40}$/.test(username)) return fail("اسم المستخدم يجب أن يكون 3–40 حرفًا إنجليزيًا أو رقمًا أو . _ -.");
    if (displayName.length < 2 || displayName.length > 80) return fail("اكتب اسمًا صحيحًا.");
    if (password.length < 14 || password.length > 200) return fail("كلمة المرور يجب أن تكون 14 حرفًا على الأقل.");
    if (!["admin","viewer"].includes(role)) return fail("الدور غير صالح.");
    try {
      await env.DB.prepare("INSERT INTO users (id, username, display_name, password_hash, role) VALUES (?, ?, ?, ?, ?)")
        .bind(id(), username, displayName, await passwordHash(password), role).run();
    } catch { return fail("اسم المستخدم موجود بالفعل أو تعذر إنشاء الحساب.", 409); }
    await audit(env, auth.user.id, "create_user", `${username}:${role}`);
    return json({ ok: true });
  }

  if (path === "/api/password" && request.method === "POST") {
    const auth = await requireUser(request, env);
    if (auth.error) return auth.error;
    let b; try { b = await bodyJson(request, 10000); } catch { return fail("بيانات غير صحيحة."); }
    const row = await env.DB.prepare("SELECT password_hash FROM users WHERE id=?").bind(auth.user.id).first();
    if (!await verifyPassword(String(b.currentPassword || ""), row.password_hash)) return fail("كلمة المرور الحالية غير صحيحة.", 403);
    const newPassword = String(b.newPassword || "");
    if (newPassword.length < 14 || newPassword.length > 200) return fail("كلمة المرور الجديدة يجب أن تكون 14 حرفًا على الأقل.");
    await env.DB.prepare("UPDATE users SET password_hash=? WHERE id=?").bind(await passwordHash(newPassword), auth.user.id).run();
    await env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(auth.user.id).run();
    await audit(env, auth.user.id, "change_password", "");
    return json({ ok: true }, 200, { "set-cookie": clearCookie() });
  }

  return fail("المسار غير موجود.", 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) {
      try { return await api(request, env); }
      catch (e) {
        console.error("API error", e?.message || e);
        return fail("حدث خطأ داخلي. راجع سجلات Cloudflare.", 500);
      }
    }
    return env.ASSETS.fetch(request);
  }
};
