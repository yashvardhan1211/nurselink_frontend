require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'nurselink_secret_2024';
const PORT = process.env.PORT || 3000;

// DB connection
const pool = process.env.DATABASE_URL
  ? new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } })
  : null;

// ── AUTH MIDDLEWARE ──────────────────────────────────────────────────────────
function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(h.replace('Bearer ', ''), JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
}

// ── HEALTH ───────────────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => res.json({ status: 'ok', time: new Date() }));

// ── AUTH ─────────────────────────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!pool) return res.status(503).json({ error: 'No database configured' });
  try {
    const r = await pool.query('SELECT * FROM staff WHERE email=$1', [email]);
    const user = r.rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, id: user.id, name: user.name, role: user.role, department: user.department });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── STAFF ────────────────────────────────────────────────────────────────────
app.get('/api/staff', auth, async (req, res) => {
  if (!pool) return res.json([]);
  try {
    const r = await pool.query('SELECT id,name,role,department,specialty,emp_id,email,available FROM staff ORDER BY role,name');
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/staff', auth, async (req, res) => {
  const { name, role, department, specialty, emp_id, email, password } = req.body;
  if (!pool) return res.status(503).json({ error: 'No DB' });
  try {
    const hash = await bcrypt.hash(password || 'password123', 10);
    const r = await pool.query(
      'INSERT INTO staff(name,role,department,specialty,emp_id,email,password_hash) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *',
      [name, role, department||'', specialty||'', emp_id||'', email||'', hash]
    );
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── PATIENTS ─────────────────────────────────────────────────────────────────
app.get('/api/patients', auth, async (req, res) => {
  if (!pool) return res.json([]);
  try {
    const status = req.query.status;
    const q = status
      ? 'SELECT * FROM patients WHERE status=$1 ORDER BY created_at DESC'
      : "SELECT * FROM patients WHERE status IN ('Active','OPD') ORDER BY created_at DESC";
    const r = status ? await pool.query(q, [status]) : await pool.query(q);
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/patients', auth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No DB' });
  const b = req.body;
  try {
    const r = await pool.query(
      `INSERT INTO patients(name,age,gender,phone,diagnosis,icd_code,bed,doctor_id,nurse_id,
       admission_type,chief_complaint,allergies,blood_group,status,diag_type,
       height_cm,weight_kg,bmi,address,pincode,chronic_diseases,
       insurance_company,insurance_policy,insurance_member,insurance_type)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25)
       RETURNING *`,
      [b.name,b.age,b.gender,b.phone,b.diagnosis||'',b.icd_code||'Z00',b.bed||null,
       b.doctor_id||null,b.nurse_id||null,b.admission_type||'OPD Consultation',
       b.chief_complaint||'',b.allergies||'None Known',b.blood_group||null,
       b.status||'OPD',b.diag_type||'Provisional',
       b.height_cm||null,b.weight_kg||null,b.bmi||null,
       b.address||null,b.pincode||null,b.chronic_diseases||null,
       b.insurance_company||null,b.insurance_policy||null,b.insurance_member||null,b.insurance_type||null]
    );
    io.emit('patient:admitted', { patientId: r.rows[0].id });
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/patients/:id', auth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No DB' });
  const b = req.body;
  const fields = [], vals = [];
  let i = 1;
  const allowed = ['status','bed','doctor_id','nurse_id','diagnosis','icd_code',
    'chief_complaint','blood_group','allergies','admission_type','diag_type'];
  allowed.forEach(k => { if (b[k] !== undefined) { fields.push(`${k}=$${i++}`); vals.push(b[k]); } });
  if (!fields.length) return res.json({ ok: true });
  vals.push(req.params.id);
  try {
    const r = await pool.query(`UPDATE patients SET ${fields.join(',')} WHERE id=$${i} RETURNING *`, vals);
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/patients/:id/discharge', auth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No DB' });
  try {
    const r = await pool.query(
      "UPDATE patients SET status='Discharged',discharge_condition=$1,discharge_time=NOW() WHERE id=$2 RETURNING *",
      [req.body.condition||'Stable', req.params.id]
    );
    io.emit('patient:discharged', { patientId: req.params.id });
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── VITALS ───────────────────────────────────────────────────────────────────
app.post('/api/vitals/:pid', auth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No DB' });
  const b = req.body; const pid = req.params.pid;
  try {
    const r = await pool.query(
      `INSERT INTO vitals(patient_id,bp_sys,bp_dia,pulse,spo2,temperature,resp_rate,gcs,
       urine_output,blood_glucose,drain_output,pain_score,notes,recorded_by_id)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING *`,
      [pid,b.bp_sys,b.bp_dia,b.pulse,b.spo2,b.temperature,b.resp_rate,
       b.gcs||15,b.urine_output||40,b.blood_glucose||100,b.drain_output||0,
       b.pain_score||0,b.notes||'',req.user.id]
    );
    io.emit('vitals:new', { ...r.rows[0], patient_id: pid });
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── PRESCRIPTIONS ────────────────────────────────────────────────────────────
app.post('/api/prescriptions/:pid', auth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No DB' });
  const b = req.body; const pid = req.params.pid;
  try {
    const r = await pool.query(
      `INSERT INTO prescriptions(patient_id,drug,dose,route,frequency,duration,instructions,prescribed_by_id,status)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,'active') RETURNING *`,
      [pid,b.drug,b.dose||'',b.route||'Oral',b.frequency||'',b.duration||'',b.instructions||'',req.user.id]
    );
    io.emit('prescription:new', { ...r.rows[0], patient_id: pid });
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/prescriptions/:id/discontinue', auth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No DB' });
  try {
    const r = await pool.query("UPDATE prescriptions SET status='discontinued' WHERE id=$1 RETURNING *", [req.params.id]);
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── LABS ─────────────────────────────────────────────────────────────────────
app.post('/api/labs/:pid', auth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No DB' });
  const pid = req.params.pid;
  try {
    const results = [];
    for (const t of (req.body.tests||[])) {
      const r = await pool.query(
        'INSERT INTO lab_orders(patient_id,test_name,category,priority,ordered_by_id) VALUES($1,$2,$3,$4,$5) RETURNING *',
        [pid,t.test_name,t.category||'',t.priority||'Routine',req.user.id]
      );
      results.push(r.rows[0]);
    }
    res.json(results);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── ALERTS ───────────────────────────────────────────────────────────────────
app.get('/api/alerts', auth, async (req, res) => {
  if (!pool) return res.json([]);
  try {
    const r = await pool.query('SELECT * FROM alerts ORDER BY created_at DESC LIMIT 50');
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/alerts/:id/acknowledge', auth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No DB' });
  try {
    const r = await pool.query('UPDATE alerts SET acknowledged_by=$1,acknowledged_at=NOW() WHERE id=$2 RETURNING *', [req.user.id, req.params.id]);
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── QUEUE ────────────────────────────────────────────────────────────────────
app.get('/api/queue', auth, async (req, res) => {
  if (!pool) return res.json([]);
  try {
    const r = await pool.query(
      `SELECT q.*,p.name,p.ehr_id,p.chief_complaint FROM opd_queue q
       JOIN patients p ON p.id=q.patient_id
       WHERE q.status IN ('Waiting','Called') ORDER BY q.created_at ASC`
    );
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/queue/:id/status', auth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No DB' });
  try {
    const r = await pool.query('UPDATE opd_queue SET status=$1 WHERE id=$2 RETURNING *', [req.body.status, req.params.id]);
    io.emit('queue:update');
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── NOTES ────────────────────────────────────────────────────────────────────
app.post('/api/notes/consult/:pid', auth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No DB' });
  const b = req.body;
  try {
    const r = await pool.query(
      'INSERT INTO consult_notes(patient_id,subjective,objective,assessment,plan,created_by_id) VALUES($1,$2,$3,$4,$5,$6) RETURNING *',
      [req.params.pid,b.subjective||'',b.objective||'',b.assessment||'',b.plan||'',req.user.id]
    );
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── MAR ──────────────────────────────────────────────────────────────────────
app.post('/api/mar', auth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No DB' });
  try {
    const r = await pool.query(
      'INSERT INTO mar(prescription_id,patient_id,status,given_by_id) VALUES($1,$2,$3,$4) RETURNING *',
      [req.body.prescription_id,req.body.patient_id,req.body.status,req.user.id]
    );
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── SOCKET ───────────────────────────────────────────────────────────────────
io.on('connection', socket => {
  socket.on('sos:trigger', data => io.emit('sos:trigger', data));
  socket.on('sos:acknowledge', data => io.emit('sos:acknowledge', data));
  socket.on('chat:message', data => io.emit('chat:message', data));
});

server.listen(PORT, () => console.log(`NurseLink backend running on port ${PORT}`));
