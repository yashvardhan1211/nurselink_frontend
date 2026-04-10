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

const pool = process.env.DATABASE_URL
  ? new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } })
  : null;

function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(h.replace('Bearer ', ''), JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
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
      [name, role, department||'', specialty||department||'', emp_id||'', email||'', hash]
    );
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/staff/:id', auth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No DB' });
  const { name, role, department, specialty, emp_id, password } = req.body;
  try {
    const fields = [], vals = [];
    let i = 1;
    if (name)       { fields.push(`name=$${i++}`);       vals.push(name); }
    if (role)       { fields.push(`role=$${i++}`);       vals.push(role); }
    if (department) { fields.push(`department=$${i++}`); vals.push(department); }
    if (specialty)  { fields.push(`specialty=$${i++}`);  vals.push(specialty); }
    if (emp_id)     { fields.push(`emp_id=$${i++}`);     vals.push(emp_id); }
    if (password)   { const h = await bcrypt.hash(password, 10); fields.push(`password_hash=$${i++}`); vals.push(h); }
    if (!fields.length) return res.json({ ok: true });
    vals.push(req.params.id);
    const r = await pool.query(`UPDATE staff SET ${fields.join(',')} WHERE id=$${i} RETURNING *`, vals);
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/staff/:id', auth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No DB' });
  try {
    await pool.query('DELETE FROM staff WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
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
       b.doctor_id ? parseInt(b.doctor_id)||null : null,
       b.nurse_id  ? parseInt(b.nurse_id)||null  : null,
       b.admission_type||'OPD Consultation',
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
  allowed.forEach(k => {
    if (b[k] !== undefined) {
      fields.push(`${k}=$${i++}`);
      if ((k === 'doctor_id' || k === 'nurse_id') && b[k] !== null)
        vals.push(parseInt(b[k]) || null);
      else vals.push(b[k]);
    }
  });
  if (!fields.length) return res.json({ ok: true });
  vals.push(req.params.id);
  try {
    const r = await pool.query(`UPDATE patients SET ${fields.join(',')} WHERE id=$${i} RETURNING *`, vals);
    res.json(r.rows[0] || { ok: true });
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
app.get('/api/vitals/:pid', auth, async (req, res) => {
  if (!pool) return res.json([]);
  try {
    const r = await pool.query(
      `SELECT v.*,s.name as recorded_by_name FROM vitals v
       LEFT JOIN staff s ON s.id=v.recorded_by_id
       WHERE v.patient_id=$1 ORDER BY v.recorded_at DESC`,
      [req.params.pid]
    );
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

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
    const vitalsRow = { ...r.rows[0], patient_id: pid, recorded_by_name: req.user.name };
    io.emit('vitals:new', vitalsRow);

    // Auto-generate alerts from vital thresholds
    const alerts = [];
    const sbp = b.bp_sys, dbp = b.bp_dia, pulse = b.pulse, spo2 = b.spo2;
    const temp = parseFloat(b.temperature)||0, rr = b.resp_rate||0, uo = b.urine_output||40;
    if (sbp > 180)       alerts.push({ type:'critical', title:'BP CRITICAL',    message:`BP ${sbp}/${dbp} — Hypertensive Emergency` });
    else if (sbp > 160)  alerts.push({ type:'warning',  title:'BP HIGH',        message:`BP ${sbp}/${dbp} — Elevated` });
    if (sbp < 90)        alerts.push({ type:'critical', title:'HYPOTENSION',    message:`BP ${sbp}/${dbp} — Check for shock` });
    if (spo2 < 92)       alerts.push({ type:'critical', title:'SpO2 CRITICAL',  message:`SpO2 ${spo2}% — Severe hypoxia` });
    else if (spo2 < 95)  alerts.push({ type:'warning',  title:'SpO2 LOW',       message:`SpO2 ${spo2}% — Below normal` });
    if (pulse > 130)     alerts.push({ type:'critical', title:'TACHYCARDIA',    message:`Pulse ${pulse} bpm — Severe` });
    if (pulse < 50)      alerts.push({ type:'critical', title:'BRADYCARDIA',    message:`Pulse ${pulse} bpm` });
    if (temp > 39.5)     alerts.push({ type:'critical', title:'HIGH FEVER',     message:`Temp ${temp}°C — Hyperpyrexia` });
    else if (temp > 38.5)alerts.push({ type:'warning',  title:'FEVER',          message:`Temp ${temp}°C` });
    if (uo < 20)         alerts.push({ type:'warning',  title:'OLIGURIA',       message:`Urine Output ${uo} ml/hr — Low` });
    if (rr > 25)         alerts.push({ type:'warning',  title:'TACHYPNEA',      message:`RR ${rr}/min — High` });

    if (alerts.length > 0) {
      const savedAlerts = [];
      // Fetch patient name for the emit
      const ptRow = await pool.query('SELECT name FROM patients WHERE id=$1', [pid]).catch(() => ({ rows: [] }));
      const patientName = ptRow.rows[0]?.name || '';
      for (const a of alerts) {
        const ar = await pool.query(
          'INSERT INTO alerts(patient_id,type,title,message) VALUES($1,$2,$3,$4) RETURNING *',
          [pid, a.type, a.title, a.message]
        );
        savedAlerts.push({ ...ar.rows[0], patient_name: patientName });
      }
      io.emit('alert:new', { patientId: String(pid), patientName, alerts: savedAlerts });
    }

    // Emit notification for new vitals entry (nurse → doctor)
    io.emit('notification:new', {
      role: 'Doctor',
      title: `New Vitals: ${req.user.name}`,
      body: `${ptRow.rows[0]?.name || 'Patient #'+pid} — BP ${sbp}/${dbp}, SpO2 ${spo2}%`,
      time: new Date().toISOString(),
      patientId: String(pid),
      patientName: ptRow.rows[0]?.name || '',
    });

    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── PRESCRIPTIONS ─────────────────────────────────────────────────────────────
// GET all active prescriptions (for pharmacist)
app.get('/api/prescriptions', auth, async (req, res) => {
  if (!pool) return res.json([]);
  try {
    const r = await pool.query(
      `SELECT pr.*,p.name as patient_name,p.ehr_id,s.name as prescribed_by_name
       FROM prescriptions pr
       JOIN patients p ON p.id=pr.patient_id
       LEFT JOIN staff s ON s.id=pr.prescribed_by_id
       WHERE pr.status='active'
       ORDER BY pr.created_at DESC`
    );
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET prescriptions for a specific patient
app.get('/api/prescriptions/:pid', auth, async (req, res) => {
  if (!pool) return res.json([]);
  try {
    const r = await pool.query(
      `SELECT pr.*,s.name as prescribed_by_name FROM prescriptions pr
       LEFT JOIN staff s ON s.id=pr.prescribed_by_id
       WHERE pr.patient_id=$1 ORDER BY pr.created_at DESC`,
      [req.params.pid]
    );
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/prescriptions/:pid', auth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No DB' });
  const b = req.body; const pid = req.params.pid;
  try {
    const r = await pool.query(
      `INSERT INTO prescriptions(patient_id,drug,dose,route,frequency,duration,instructions,prescribed_by_id,status)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,'active') RETURNING *`,
      [pid,b.drug,b.dose||'',b.route||'Oral',b.frequency||'',b.duration||'',b.instructions||'',req.user.id]
    );
    const row = { ...r.rows[0], patient_id: pid, prescribed_by_name: req.user.name };
    io.emit('prescription:new', row);
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

// ── LAB ORDERS ────────────────────────────────────────────────────────────────
// GET all pending lab orders (for lab tech)
app.get('/api/labs', auth, async (req, res) => {
  if (!pool) return res.json([]);
  try {
    const r = await pool.query(
      `SELECT lo.*,p.name as patient_name,p.ehr_id,s.name as ordered_by_name
       FROM lab_orders lo
       JOIN patients p ON p.id=lo.patient_id
       LEFT JOIN staff s ON s.id=lo.ordered_by_id
       ORDER BY lo.created_at DESC`
    );
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET lab orders for a specific patient
app.get('/api/labs/:pid', auth, async (req, res) => {
  if (!pool) return res.json([]);
  try {
    const r = await pool.query(
      `SELECT lo.*,s.name as ordered_by_name FROM lab_orders lo
       LEFT JOIN staff s ON s.id=lo.ordered_by_id
       WHERE lo.patient_id=$1 ORDER BY lo.created_at DESC`,
      [req.params.pid]
    );
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

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
    io.emit('labs:new', { patient_id: pid, orders: results, ordered_by_name: req.user.name });
    res.json(results);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/labs/:id/result', auth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No DB' });
  try {
    const status = req.body.status || 'Result Available';
    const result = req.body.result !== undefined ? req.body.result : null;
    const report_url = req.body.report_url || null;
    const report_name = req.body.report_name || null;
    const r = await pool.query(
      'UPDATE lab_orders SET result=$1,status=$2,report_url=$3,report_name=$4 WHERE id=$5 RETURNING *',
      [result, status, report_url, report_name, req.params.id]
    );
    io.emit('labs:result', { ...r.rows[0] });
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── CHAT ──────────────────────────────────────────────────────────────────────
// GET chat messages for a patient
app.get('/api/chat/:pid', auth, async (req, res) => {
  if (!pool) return res.json([]);
  try {
    const r = await pool.query(
      `SELECT c.*,s.name as sender_name,s.role as sender_role FROM chat_messages c
       LEFT JOIN staff s ON s.id=c.sender_id
       WHERE c.patient_id=$1 ORDER BY c.sent_at ASC`,
      [req.params.pid]
    );
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST a chat message
app.post('/api/chat/:pid', auth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No DB' });
  try {
    const r = await pool.query(
      'INSERT INTO chat_messages(patient_id,sender_id,message) VALUES($1,$2,$3) RETURNING *',
      [req.params.pid, req.user.id, req.body.message]
    );
    const msg = {
      ...r.rows[0],
      patient_id: req.params.pid,
      sender_name: req.user.name,
      sender_role: req.user.role,
    };
    io.emit('chat:message', msg);
    // Notify the opposite role
    const targetRole = req.user.role === 'Doctor' ? 'Nurse' : 'Doctor';
    // Fetch patient name for the notification
    const ptInfo = await pool.query('SELECT name FROM patients WHERE id=$1', [req.params.pid]).catch(() => ({ rows: [] }));
    const ptName = ptInfo.rows[0]?.name || '';
    io.emit('notification:new', {
      role: targetRole,
      title: `Message from ${req.user.name}`,
      body: `${ptName || 'Patient #'+req.params.pid} — ${req.body.message?.substring(0, 60)}`,
      time: new Date().toISOString(),
      patientId: String(req.params.pid),
      patientName: ptName,
    });
    res.json(msg);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── ALERTS ───────────────────────────────────────────────────────────────────
app.get('/api/alerts', auth, async (req, res) => {
  if (!pool) return res.json([]);
  try {
    const r = await pool.query(
      `SELECT a.*, p.name as patient_name, p.ehr_id
       FROM alerts a
       LEFT JOIN patients p ON p.id = a.patient_id
       ORDER BY a.created_at DESC LIMIT 100`
    );
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/alerts/:id/acknowledge', auth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No DB' });
  try {
    const r = await pool.query('UPDATE alerts SET acknowledged_by=$1,acknowledged_at=NOW() WHERE id=$2 RETURNING *', [req.user.id, req.params.id]);
    io.emit('alert:acked', { id: req.params.id, by: req.user.name });
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── QUEUE ────────────────────────────────────────────────────────────────────
app.get('/api/queue', auth, async (req, res) => {
  if (!pool) return res.json([]);
  try {
    const r = await pool.query(
      `SELECT q.*,p.name,p.ehr_id,p.chief_complaint,p.doctor_id FROM opd_queue q
       JOIN patients p ON p.id=q.patient_id
       WHERE q.status IN ('Waiting','Called') ORDER BY q.created_at ASC`
    );
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/queue', auth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No DB' });
  try {
    const r = await pool.query(
      'INSERT INTO opd_queue(patient_id,doctor_id,status) VALUES($1,$2,$3) RETURNING *',
      [req.body.patient_id, req.body.doctor_id||null, 'Waiting']
    );
    io.emit('queue:update');
    res.json(r.rows[0]);
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
app.get('/api/notes/consult/:pid', auth, async (req, res) => {
  if (!pool) return res.json([]);
  try {
    const r = await pool.query(
      `SELECT n.*,s.name as created_by_name FROM consult_notes n
       LEFT JOIN staff s ON s.id=n.created_by_id
       WHERE n.patient_id=$1 ORDER BY n.created_at DESC`,
      [req.params.pid]
    );
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

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

// ── NETWORK ───────────────────────────────────────────────────────────────────
app.get('/api/network/posts', auth, async (req, res) => {
  if (!pool) return res.json([]);
  try {
    const r = await pool.query(`
      SELECT p.*, s.name as author_name, s.department as author_dept,
        (SELECT COUNT(*) FROM network_post_likes l WHERE l.post_id=p.id) as like_count,
        (SELECT COUNT(*) FROM network_post_replies r WHERE r.post_id=p.id) as reply_count
      FROM network_posts p
      LEFT JOIN staff s ON s.id=p.author_id
      ORDER BY p.created_at DESC LIMIT 50`);
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/network/posts', auth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No DB' });
  const { text, tag, case_label, case_history } = req.body;
  try {
    const r = await pool.query(
      'INSERT INTO network_posts(author_id,text,tag,case_label,case_history) VALUES($1,$2,$3,$4,$5) RETURNING *',
      [req.user.id, text, tag||'Discussion', case_label||null, case_history ? JSON.stringify(case_history) : null]
    );
    io.emit('network:post', { ...r.rows[0], author_name: req.user.name });
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/network/posts/:id/like', auth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No DB' });
  try {
    const exists = await pool.query('SELECT 1 FROM network_post_likes WHERE post_id=$1 AND staff_id=$2', [req.params.id, req.user.id]);
    if (exists.rows.length) {
      await pool.query('DELETE FROM network_post_likes WHERE post_id=$1 AND staff_id=$2', [req.params.id, req.user.id]);
    } else {
      await pool.query('INSERT INTO network_post_likes(post_id,staff_id) VALUES($1,$2)', [req.params.id, req.user.id]);
    }
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/network/posts/:id/replies', auth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No DB' });
  try {
    const r = await pool.query(
      'INSERT INTO network_post_replies(post_id,author_id,text) VALUES($1,$2,$3) RETURNING *',
      [req.params.id, req.user.id, req.body.text]
    );
    io.emit('network:reply', { ...r.rows[0], author_name: req.user.name, post_id: req.params.id });
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/network/dms/:peerId', auth, async (req, res) => {
  if (!pool) return res.json([]);
  try {
    const r = await pool.query(
      `SELECT d.*, s.name as sender_name FROM network_dms d
       LEFT JOIN staff s ON s.id=d.sender_id
       WHERE (d.sender_id=$1 AND d.receiver_id=$2) OR (d.sender_id=$2 AND d.receiver_id=$1)
       ORDER BY d.created_at ASC`,
      [req.user.id, req.params.peerId]
    );
    // Mark as read
    await pool.query('UPDATE network_dms SET read=true WHERE receiver_id=$1 AND sender_id=$2', [req.user.id, req.params.peerId]);
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/network/dms/:toId', auth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No DB' });
  try {
    const r = await pool.query(
      'INSERT INTO network_dms(sender_id,receiver_id,text) VALUES($1,$2,$3) RETURNING *',
      [req.user.id, req.params.toId, req.body.text]
    );
    io.emit('network:dm', { ...r.rows[0], sender_name: req.user.name });
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── SOCKET ───────────────────────────────────────────────────────────────────
io.on('connection', socket => {
  socket.on('sos:trigger', data => io.emit('sos:trigger', data));
  socket.on('sos:acknowledge', data => io.emit('sos:acknowledge', data));
  // Chat via socket (fallback for non-DB mode)
  socket.on('chat:message', data => io.emit('chat:message', data));
});

server.listen(PORT, () => console.log(`NurseLink backend running on port ${PORT}`));
