from pathlib import Path
import zipfile, textwrap, os

root = Path("/mnt/data/negareh-attendance")
(root / "public").mkdir(parents=True, exist_ok=True)

files = {
"package.json": r'''{
  "name": "negareh-attendance",
  "version": "1.0.0",
  "private": true,
  "description": "سامانه نمونه حضور و غیاب با رابط فارسی",
  "scripts": { "start": "node server.js" },
  "dependencies": {
    "bcryptjs": "^2.4.3",
    "better-sqlite3": "^11.8.1",
    "express": "^4.21.2",
    "express-rate-limit": "^7.5.0",
    "express-session": "^1.18.1",
    "helmet": "^8.0.0"
  }
}''',
".env.example": r'''PORT=3000
SESSION_SECRET=replace-with-a-long-random-secret
ADMIN_USERNAME=schooladmin
ADMIN_PASSWORD=replace-with-a-strong-password
# Keep this secret private and unchanged after deployment:
LOOKUP_SECRET=replace-with-another-long-random-secret
''',
".gitignore": r'''node_modules/
.env
data/
''',
"server.js": r'''const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const required = ["SESSION_SECRET", "ADMIN_USERNAME", "ADMIN_PASSWORD", "LOOKUP_SECRET"];
for (const key of required) {
  if (!process.env[key]) {
    console.error(`Missing environment variable: ${key}. Copy .env.example to .env and set values.`);
    process.exit(1);
  }
}
if (process.env.SESSION_SECRET.length < 32 || process.env.LOOKUP_SECRET.length < 32) {
  console.error("SESSION_SECRET and LOOKUP_SECRET must each be at least 32 characters.");
  process.exit(1);
}

const fs = require("fs");
const dataDir = path.join(__dirname, "data");
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);
const db = new Database(path.join(dataDir, "attendance.sqlite"));
db.pragma("journal_mode = WAL");
db.exec(`
  CREATE TABLE IF NOT EXISTS students (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    national_key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    pin_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS attendance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL REFERENCES students(id),
    attendance_date TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('غیبت موجه','غیبت غیرموجه','تأخیر')),
    note TEXT DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

function nationalKey(nationalId) {
  return crypto.createHmac("sha256", process.env.LOOKUP_SECRET)
    .update(nationalId).digest("hex");
}
function validNationalId(value) {
  return /^\d{10}$/.test(value);
}
function isAdmin(req, res, next) {
  if (req.session.role !== "admin") return res.status(401).json({ error: "ابتدا وارد پنل مدیریت شوید." });
  next();
}
function isStudent(req, res, next) {
  if (req.session.role !== "student") return res.status(401).json({ error: "ابتدا وارد حساب دانش‌آموز شوید." });
  next();
}

app.use(helmet());
app.use(express.json({ limit: "20kb" }));
app.use(session({
  name: "negareh.sid",
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
    maxAge: 30 * 60 * 1000
  }
}));
app.use(express.static(path.join(__dirname, "public")));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: true, legacyHeaders: false,
  message: { error: "تعداد تلاش‌ها زیاد است. کمی بعد دوباره امتحان کنید." } });
app.post("/api/admin/login", loginLimiter, (req, res) => {
  const { username, password } = req.body || {};
  const ok = username === process.env.ADMIN_USERNAME &&
    typeof password === "string" &&
    crypto.timingSafeEqual(
      Buffer.from(crypto.createHash("sha256").update(password).digest("hex")),
      Buffer.from(crypto.createHash("sha256").update(process.env.ADMIN_PASSWORD).digest("hex"))
    );
  if (!ok) return res.status(401).json({ error: "نام کاربری یا رمز عبور نادرست است." });
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "خطا در ورود." });
    req.session.role = "admin";
    res.json({ ok: true });
  });
});

app.post("/api/student/login", loginLimiter, async (req, res) => {
  const { nationalId, pin } = req.body || {};
  if (!validNationalId(nationalId) || typeof pin !== "string" || pin.length < 6 || pin.length > 64) {
    return res.status(400).json({ error: "کد ملی یا رمز تأیید معتبر نیست." });
  }
  const student = db.prepare("SELECT id, name, pin_hash FROM students WHERE national_key = ?")
    .get(nationalKey(nationalId));
  if (!student || !(await bcrypt.compare(pin, student.pin_hash))) {
    return res.status(401).json({ error: "کد ملی یا رمز تأیید نادرست است." });
  }
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "خطا در ورود." });
    req.session.role = "student";
    req.session.studentId = student.id;
    res.json({ ok: true, name: student.name });
  });
});

app.post("/api/logout", (req, res) => req.session.destroy(() => res.json({ ok: true })));

app.post("/api/students", isAdmin, async (req, res) => {
  const { nationalId, name, pin } = req.body || {};
  if (!validNationalId(nationalId)) return res.status(400).json({ error: "کد ملی باید ۱۰ رقم باشد." });
  if (typeof name !== "string" || name.trim().length < 2 || name.trim().length > 80)
    return res.status(400).json({ error: "نام دانش‌آموز را درست وارد کنید." });
  if (typeof pin !== "string" || !/^\d{8}$/.test(pin))
    return res.status(400).json({ error: "رمز اولیه باید ۸ رقم باشد." });
  try {
    const hash = await bcrypt.hash(pin, 12);
    db.prepare("INSERT INTO students (national_key, name, pin_hash) VALUES (?, ?, ?)")
      .run(nationalKey(nationalId), name.trim(), hash);
    res.json({ ok: true, message: "دانش‌آموز ثبت شد. رمز اولیه را محرمانه به خود دانش‌آموز تحویل دهید." });
  } catch {
    res.status(409).json({ error: "این کد ملی قبلاً ثبت شده یا اطلاعات تکراری است." });
  }
});

app.post("/api/attendance", isAdmin, (req, res) => {
  const { nationalId, date, status, note = "" } = req.body || {};
  if (!validNationalId(nationalId)) return res.status(400).json({ error: "کد ملی باید ۱۰ رقم باشد." });
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date || "")) return res.status(400).json({ error: "تاریخ معتبر نیست." });
  if (!["غیبت موجه", "غیبت غیرموجه", "تأخیر"].includes(status))
    return res.status(400).json({ error: "نوع وضعیت معتبر نیست." });
  if (typeof note !== "string" || note.length > 250) return res.status(400).json({ error: "توضیحات بیش از حد طولانی است." });
  const student = db.prepare("SELECT id FROM students WHERE national_key = ?").get(nationalKey(nationalId));
  if (!student) return res.status(404).json({ error: "دانش‌آموزی با این کد ملی ثبت نشده است." });
  db.prepare("INSERT INTO attendance (student_id, attendance_date, status, note) VALUES (?, ?, ?, ?)")
    .run(student.id, date, status, note.trim());
  res.json({ ok: true, message: "وضعیت حضور و غیاب ثبت شد." });
});

app.get("/api/admin/attendance", isAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT s.name, a.attendance_date AS date, a.status, a.note
    FROM attendance a JOIN students s ON s.id = a.student_id
    ORDER BY a.attendance_date DESC, a.id DESC LIMIT 300
  `).all();
  res.json(rows);
});

app.get("/api/student/attendance", isStudent, (req, res) => {
  const student = db.prepare("SELECT name FROM students WHERE id = ?").get(req.session.studentId);
  const rows = db.prepare(`
    SELECT attendance_date AS date, status, note
    FROM attendance WHERE student_id = ?
    ORDER BY attendance_date DESC, id DESC
  `).all(req.session.studentId);
  res.json({ name: student.name, records: rows });
});

app.get("/api/session", (req, res) => res.json({ role: req.session.role || null }));
app.listen(PORT, () => console.log(`Negareh Attendance running on http://localhost:${PORT}`));
''',
"public/index.html": r'''<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>نگار حضور | سامانه حضور و غیاب</title>
<link rel="stylesheet" href="/style.css">
</head>
<body>
<div class="ornament top"></div>
<header class="hero">
  <div class="seal">✺</div>
  <p class="eyebrow">سامانه هوشمند مدرسه</p>
  <h1>نگار حضور</h1>
  <p class="subtitle">سامانه ثبت و مشاهده وضعیت حضور و غیاب دانش‌آموزان</p>
  <div class="tile">❖　✦　❖</div>
</header>

<main class="container">
  <nav class="tabs">
    <button class="tab active" data-tab="student">ورود دانش‌آموز</button>
    <button class="tab" data-tab="admin">ورود مدیریت</button>
  </nav>

  <section id="student" class="panel">
    <h2>مشاهده سوابق حضور و غیاب</h2>
    <p class="muted">برای حفظ محرمانگی، ورود با کد ملی و رمز تأیید اختصاصی انجام می‌شود.</p>
    <form id="studentLogin">
      <label>کد ملی</label><input name="nationalId" inputmode="numeric" maxlength="10" pattern="[0-9]{10}" placeholder="۱۰ رقم کد ملی" required>
      <label>رمز تأیید ۸ رقمی</label><input name="pin" inputmode="numeric" maxlength="8" pattern="[0-9]{8}" placeholder="رمز دریافتی از مدرسه" required>
      <button class="primary">ورود و مشاهده سوابق</button>
    </form>
    <div id="studentResult" class="result"></div>
  </section>

  <section id="admin" class="panel hidden">
    <h2>پنل مدیریت</h2>
    <form id="adminLogin">
      <label>نام کاربری مدیریت</label><input name="username" autocomplete="username" required>
      <label>رمز عبور</label><input name="password" type="password" autocomplete="current-password" required>
      <button class="primary">ورود به مدیریت</button>
    </form>
    <div id="adminArea" class="hidden">
      <div class="divider"></div>
      <h3>ثبت دانش‌آموز</h3>
      <form id="addStudent">
        <label>نام و نام خانوادگی</label><input name="name" required maxlength="80">
        <label>کد ملی</label><input name="nationalId" inputmode="numeric" maxlength="10" pattern="[0-9]{10}" required>
        <label>رمز اولیه ۸ رقمی</label><input name="pin" inputmode="numeric" maxlength="8" pattern="[0-9]{8}" required>
        <button class="secondary">ثبت دانش‌آموز</button>
      </form>
      <div class="divider"></div>
      <h3>ثبت غیبت یا تأخیر</h3>
      <form id="addAttendance">
        <label>کد ملی دانش‌آموز</label><input name="nationalId" inputmode="numeric" maxlength="10" pattern="[0-9]{10}" required>
        <label>تاریخ (میلادی، مانند 2026-11-12)</label><input name="date" type="date" required>
        <label>وضعیت</label>
        <select name="status"><option>غیبت غیرموجه</option><option>غیبت موجه</option><option>تأخیر</option></select>
        <label>توضیحات (اختیاری)</label><input name="note" maxlength="250">
        <button class="secondary">ثبت وضعیت</button>
      </form>
      <div class="divider"></div>
      <div class="row"><h3>آخرین ثبت‌ها</h3><button id="refresh" type="button" class="plain">به‌روزرسانی</button></div>
      <div id="adminRecords"></div>
      <button id="logout" class="logout" type="button">خروج از حساب مدیریت</button>
    </div>
  </section>
  <p id="message" role="status" class="message"></p>
</main>
<footer>✧ طراحی با الهام از کاشی‌کاری و نقوش ایرانی ✧</footer>
<div class="ornament bottom"></div>
<script src="/app.js"></script>
</body></html>''',
"public/style.css": r'''@import url('https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap');
:root{--blue:#123e59;--teal:#147d80;--gold:#c59b48;--cream:#f7f1e5;--ink:#20323b}
*{box-sizing:border-box}body{margin:0;background:var(--cream);color:var(--ink);font-family:Vazirmatn,Tahoma,sans-serif;min-height:100vh}
.ornament{height:12px;background:repeating-linear-gradient(135deg,var(--teal) 0 8px,var(--gold) 8px 12px,var(--blue) 12px 20px)}.hero{text-align:center;padding:35px 16px 24px;background:radial-gradient(circle at 50% 0,#236b78,var(--blue));color:#fff;border-bottom:5px solid var(--gold)}
.seal{width:62px;height:62px;border:2px solid #e3c57f;border-radius:50%;display:grid;place-items:center;margin:auto;font-size:38px;color:#e3c57f}.eyebrow{color:#e5cf9d;margin:12px 0 0;font-size:13px}.hero h1{font-size:36px;margin:0;font-weight:800}.subtitle{margin:5px 0 12px;color:#e6edf0}.tile{color:#e4c77e;letter-spacing:8px}
.container{max-width:680px;margin:28px auto;padding:0 16px}.tabs{display:flex;gap:8px;margin-bottom:12px}.tab{flex:1;border:1px solid #d9cba9;background:#eee5d2;color:var(--blue);border-radius:12px;padding:13px;font:inherit;font-weight:700;cursor:pointer}.tab.active{background:var(--teal);color:white;border-color:var(--teal)}
.panel{background:#fffdf8;border:1px solid #e6dcc8;border-radius:18px;padding:24px;box-shadow:0 12px 30px #173c5012}.hidden{display:none!important}h2{margin:0 0 6px;color:var(--blue)}h3{color:var(--teal);margin:0 0 12px}.muted{color:#6d7b7c;font-size:13px;margin:0 0 20px}
form{display:grid;gap:9px}label{font-size:13px;font-weight:700;color:#36545c;margin-top:5px}input,select{width:100%;padding:12px;border:1px solid #d8d4c8;border-radius:10px;background:#fff;font:inherit;outline:none}input:focus,select:focus{border-color:var(--teal);box-shadow:0 0 0 3px #147d801c}
button{font:inherit;cursor:pointer}.primary,.secondary{border:0;border-radius:11px;padding:12px;font-weight:700;margin-top:10px}.primary{background:var(--blue);color:white}.secondary{background:var(--teal);color:white}.divider{height:1px;background:#e8dfce;margin:23px 0}.result{margin-top:16px}.message{min-height:24px;text-align:center;color:var(--teal);font-size:13px}.row{display:flex;align-items:center;justify-content:space-between}.plain{border:0;background:transparent;color:var(--teal)}.logout{margin-top:20px;border:1px solid #b66b5d;color:#9c4c40;background:transparent;border-radius:9px;padding:9px 14px}
.record{border:1px solid #e8dfce;border-radius:10px;padding:12px;margin:8px 0;background:#fff}.record strong{color:var(--blue)}.empty{color:#778;padding:14px;text-align:center;background:#f6f1e7;border-radius:10px}footer{text-align:center;color:#8a754b;padding:12px 10px 30px;font-size:12px}
@media(max-width:480px){.hero h1{font-size:30px}.panel{padding:18px}.tabs{gap:5px}.tab{font-size:13px;padding:11px}}
''',
"public/app.js": r'''const $ = s => document.querySelector(s);
const message = $("#message");
function say(t, bad=false){ message.textContent=t; message.style.color=bad?"#a34437":"#147d80"; }
async function api(url, data, method="POST"){
  const r=await fetch(url,{method,headers:{"Content-Type":"application/json"},body:data?JSON.stringify(data):undefined});
  const j=await r.json().catch(()=>({error:"پاسخ نامعتبر از سرور"}));
  if(!r.ok) throw new Error(j.error||"خطا");
  return j;
}
document.querySelectorAll(".tab").forEach(b=>b.addEventListener("click",()=>{
  document.querySelectorAll(".tab").forEach(x=>x.classList.toggle("active",x===b));
  $("#student").classList.toggle("hidden",b.dataset.tab!=="student");
  $("#admin").classList.toggle("hidden",b.dataset.tab!=="admin");
  say("");
}));
$("#studentLogin").addEventListener("submit",async e=>{
  e.preventDefault(); const f=new FormData(e.target);
  try{
    const login=await api("/api/student/login",Object.fromEntries(f));
    const data=await api("/api/student/attendance",null,"GET");
    $("#studentResult").innerHTML=`<h3>سوابق ${escapeHtml(data.name)}</h3>`+
      (data.records.length?data.records.map(r=>recordHtml(r)).join(""):'<div class="empty">هنوز موردی برای شما ثبت نشده است.</div>');
    say("ورود موفق بود.");
  }catch(err){say(err.message,true);$("#studentResult").innerHTML="";}
});
$("#adminLogin").addEventListener("submit",async e=>{
  e.preventDefault();const f=new FormData(e.target);
  try{await api("/api/admin/login",Object.fromEntries(f));$("#adminArea").classList.remove("hidden");say("به پنل مدیریت خوش آمدید.");await loadRecords();}
  catch(err){say(err.message,true);}
});
$("#addStudent").addEventListener("submit",async e=>{
  e.preventDefault();const f=new FormData(e.target);
  try{const r=await api("/api/students",Object.fromEntries(f));say(r.message);e.target.reset();}
  catch(err){say(err.message,true);}
});
$("#addAttendance").addEventListener("submit",async e=>{
  e.preventDefault();const f=new FormData(e.target);
  try{const r=await api("/api/attendance",Object.fromEntries(f));say(r.message);e.target.reset();await loadRecords();}
  catch(err){say(err.message,true);}
});
function escapeHtml(v){return String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function recordHtml(r){return `<div class="record"><strong>${escapeHtml(r.date)}</strong>　${escapeHtml(r.status)}<div>${escapeHtml(r.note||"")}</div></div>`;}
async function loadRecords(){
  try{const rows=await api("/api/admin/attendance",null,"GET");$("#adminRecords").innerHTML=rows.length?rows.map(r=>`<div class="record"><strong>${escapeHtml(r.name)}</strong><div>${escapeHtml(r.date)} — ${escapeHtml(r.status)}</div><small>${escapeHtml(r.note||"")}</small></div>`).join(""):'<div class="empty">هنوز ثبتی انجام نشده است.</div>';}
  catch(err){say(err.message,true);}
}
$("#refresh").addEventListener("click",loadRecords);
$("#logout").addEventListener("click",async()=>{await api("/api/logout",{});$("#adminArea").classList.add("hidden");say("از حساب خارج شدید.");});
''',
"README-fa.md": r'''# سامانه نگار حضور

نمونه اولیه مستقل حضور و غیاب با رابط فارسی و الهام از هنر ایرانی.

## امکانات
- ورود دانش‌آموز با کد ملی + رمز تأیید ۸ رقمی
- پنل مدیریت با نام کاربری و رمز عبور
- ثبت دانش‌آموز، غیبت موجه/غیرموجه و تأخیر
- مشاهده سوابق هر دانش‌آموز و آخرین ثبت‌ها
- ذخیره اطلاعات در SQLite
- کد ملی به‌صورت متن خام در پایگاه داده ذخیره نمی‌شود؛ از HMAC برای تطبیق استفاده شده است و رمز دانش‌آموز با bcrypt هش می‌شود.

## اجرای آزمایشی روی رایانه
1. Node.js نسخه 18 یا بالاتر نصب باشد.
2. این پوشه را از حالت فشرده خارج کنید.
3. فایل `.env.example` را به `.env` تغییر نام دهید و چهار مقدار آن را با رمزهای قوی و تصادفی جایگزین کنید.
4. در ترمینال همین پوشه اجرا کنید:
   ```bash
   npm install
   npm start
   ```
5. در مرورگر باز کنید: `http://localhost:3000`

نام کاربری و رمز مدیر همان مقادیری است که در `.env` تعیین کرده‌اید. دانش‌آموزان باید ابتدا توسط مدیر ثبت شوند و رمز اولیه‌شان را محرمانه دریافت کنند.

## پیش از استفاده واقعی در مدرسه
این پروژه نمونه اولیه است و هنوز برای انتشار عمومی/استفاده رسمی مدرسه آماده تأیید امنیتی نیست. برای انتشار باید:
- روی سرور معتبر با HTTPS اجرا شود.
- از session store پایدار و امن (مانند Redis یا store سازگار با Express) استفاده شود؛ ذخیره‌ساز پیش‌فرض session فقط برای آزمایش است.
- محدودیت دسترسی شبکه، پشتیبان‌گیری رمزگذاری‌شده، ثبت رویدادهای مدیریتی، سیاست نگهداری/حذف داده و بررسی امنیتی مستقل اضافه شود.
- مدیران مجاز، رضایت‌ها و مبنای قانونی پردازش داده‌های دانش‌آموزان توسط مدرسه مشخص شوند.
- رمزهای اولیه به‌صورت امن تحویل و در اولین ورود عوض شوند؛ قابلیت تغییر/بازیابی رمز نیز پیش از استفاده واقعی افزوده شود.
- تاریخ در این نسخه با قالب میلادی وارد می‌شود.
- از کد ملی یا اطلاعات واقعی دانش‌آموزان در نسخه آزمایشی استفاده نکنید.

## نکته مهم
کد ملی به‌تنهایی رمز عبور نیست و نباید امکان مشاهده سوابق با واردکردن صرف کد ملی فراهم شود.
'''
}

for name, content in files.items():
    (root / name).write_text(content, encoding="utf-8")

zip_path = Path("/mnt/data/negareh-attendance.zip")
with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
    for p in root.rglob("*"):
        if p.is_file():
            z.write(p, p.relative_to(root.parent))
print(f"Created {zip_path} ({zip_path.stat().st_size} bytes)")
