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
    logAudit(user.id, user.name, user.role, `User logged in`, 'auth', String(user.id), null, req.ip);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── PATIENT AUTH ──────────────────────────────────────────────────────────────
app.post('/api/auth/patient-login', async (req, res) => {
  const { phone, password } = req.body;
  if (!pool) return res.status(503).json({ error: 'No database' });

  try {
    const cleanPhone = (phone || '').replace(/\D/g, '').slice(-10);
    if (cleanPhone.length !== 10) {
      return res.status(400).json({ error: 'Please enter a valid 10-digit mobile number' });
    }

    // Fetch all patients and find matching phone in JS (avoids SQL regex issues)
    const allPts = await pool.query("SELECT * FROM patients WHERE phone IS NOT NULL AND phone != ''");
    const patient = allPts.rows.find(p => {
      const stored = (p.phone || '').replace(/\D/g, '').slice(-10);
      return stored === cleanPhone;
    });

    if (!patient) {
      return res.status(401).json({ error: 'Mobile number not registered. Please contact the hospital.' });
    }

    // Accept default password 'password' — no bcrypt needed for MVP
    if ((password || '') !== 'password') {
      // Try bcrypt if patient_accounts exists
      let matched = false;
      try {
        const accRes = await pool.query('SELECT password_hash FROM patient_accounts WHERE phone=$1', [cleanPhone]);
        if (accRes.rows[0]?.password_hash) {
          matched = await bcrypt.compare(password || '', accRes.rows[0].password_hash);
        }
      } catch(e) { /* table may not exist */ }
      if (!matched) {
        return res.status(401).json({ error: 'Incorrect password. Default password is: password' });
      }
    }

    const token = jwt.sign(
      { id: patient.id, role: 'Patient', name: patient.name, phone: cleanPhone, ehrId: patient.ehr_id },
      JWT_SECRET, { expiresIn: '7d' }
    );
    console.log(`[patient-login] OK: ${patient.name} (${cleanPhone})`);
    res.json({ token, patientId: patient.id, name: patient.name, ehrId: patient.ehr_id });
  } catch (e) {
    console.error('[patient-login]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Sync: create patient_accounts for ALL existing patients who have a phone number
// Called by admin to onboard existing patients
app.post('/api/auth/sync-patient-accounts', auth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No database' });
  try {
    const patients = await pool.query("SELECT id, phone FROM patients WHERE phone IS NOT NULL AND phone != '' AND phone != 'null'");
    const defaultHash = await bcrypt.hash('password', 10);
    let created = 0, skipped = 0;
    for (const p of patients.rows) {
      try {
        const result = await pool.query(
          `INSERT INTO patient_accounts(patient_id, phone, password_hash)
           VALUES($1, $2, $3) ON CONFLICT(phone) DO NOTHING`,
          [p.id, p.phone.trim().replace(/\D/g, '').slice(-10), defaultHash]
        );
        if (result.rowCount > 0) created++;
        else skipped++;
      } catch(e) { skipped++; }
    }
    console.log(`[sync-patient-accounts] created=${created} skipped=${skipped}`);
    res.json({ ok: true, created, skipped, total: patients.rows.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Admin: reset patient password to default
app.post('/api/auth/reset-patient-password', auth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No database' });
  try {
    const { phone } = req.body;
    const cleanPhone = phone?.trim().replace(/\D/g, '').slice(-10);
    if (!cleanPhone || cleanPhone.length !== 10) return res.status(400).json({ error: 'Invalid phone' });
    const newHash = await bcrypt.hash('password', 10);
    const r = await pool.query(
      'UPDATE patient_accounts SET password_hash=$1 WHERE phone=$2 RETURNING id',
      [newHash, cleanPhone]
    );
    if (r.rowCount === 0) return res.status(404).json({ error: 'No account found for this phone' });
    res.json({ ok: true, message: 'Password reset to: password' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Change patient password
app.post('/api/auth/patient-change-password', async (req, res) => {
  const { phone, oldPassword, newPassword } = req.body;
  if (!pool) return res.status(503).json({ error: 'No database' });
  try {
    const r = await pool.query('SELECT * FROM patient_accounts WHERE phone=$1', [phone?.trim()]);
    if (!r.rows[0]) return res.status(404).json({ error: 'Account not found' });
    const ok = await bcrypt.compare(oldPassword, r.rows[0].password_hash);
    if (!ok) return res.status(401).json({ error: 'Incorrect current password' });
    const newHash = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE patient_accounts SET password_hash=$1 WHERE phone=$2', [newHash, phone?.trim()]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET patient's own data (prescriptions, labs, discharge)
app.get('/api/patient-portal/:patientId', async (req, res) => {
  if (!pool) return res.json({});
  const pid = req.params.patientId;
  try {
    const [ptRes, rxRes, labsRes, dischargeRes] = await Promise.all([
      pool.query('SELECT * FROM patients WHERE id=$1', [pid]),
      pool.query(`SELECT pr.*, s.name as prescribed_by_name FROM prescriptions pr LEFT JOIN staff s ON s.id=pr.prescribed_by_id WHERE pr.patient_id=$1 ORDER BY pr.created_at DESC`, [pid]),
      pool.query(`SELECT lo.*, s.name as ordered_by_name FROM lab_orders lo LEFT JOIN staff s ON s.id=lo.ordered_by_id WHERE lo.patient_id=$1 ORDER BY lo.created_at DESC`, [pid]),
      pool.query(`SELECT cn.*, s.name as written_by_name FROM consult_notes cn LEFT JOIN staff s ON s.id=cn.created_by_id WHERE cn.patient_id=$1 ORDER BY cn.created_at DESC`, [pid]),
    ]);
    res.json({
      patient: ptRes.rows[0] || null,
      prescriptions: rxRes.rows,
      labs: labsRes.rows,
      notes: dischargeRes.rows,
    });
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
    logAudit(req.user.id, req.user.name, req.user.role, `Admitted patient ${b.name}`, 'patient', String(r.rows[0].id), null, req.ip);

    // Auto-create patient login account if phone provided
    if (b.phone && b.phone.trim()) {
      try {
        const normalizedPhone = b.phone.trim().replace(/\D/g, '').slice(-10);
        if (normalizedPhone.length === 10) {
          const defaultHash = await bcrypt.hash('password', 10);
          await pool.query(
            `INSERT INTO patient_accounts(patient_id, phone, password_hash)
             VALUES($1, $2, $3) ON CONFLICT(phone) DO UPDATE SET patient_id=$1`,
            [r.rows[0].id, normalizedPhone, defaultHash]
          );
        }
      } catch(e) { console.warn('Patient account creation:', e.message); }
    }

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
    logAudit(req.user.id, req.user.name, req.user.role, `Discharged patient #${req.params.id} — Condition: ${req.body.condition||'Stable'}`, 'patient', req.params.id, null, req.ip);
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── CARE TEAM ─────────────────────────────────────────────────────────────────
// Ensure table exists on startup
if (pool) {
  pool.query(`
    CREATE TABLE IF NOT EXISTS patient_care_team (
      id SERIAL PRIMARY KEY,
      patient_id INTEGER REFERENCES patients(id) ON DELETE CASCADE,
      staff_id INTEGER REFERENCES staff(id) ON DELETE CASCADE,
      role TEXT NOT NULL,
      added_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(patient_id, staff_id)
    )
  `).catch(e => console.warn('care team table:', e.message));
}

// GET care team for a patient
app.get('/api/patients/:id/team', auth, async (req, res) => {
  if (!pool) return res.json([]);
  try {
    const r = await pool.query(
      `SELECT ct.*, s.name, s.role as staff_role, s.department, s.specialty, s.emp_id
       FROM patient_care_team ct
       JOIN staff s ON s.id = ct.staff_id
       WHERE ct.patient_id = $1
       ORDER BY ct.added_at ASC`,
      [req.params.id]
    );
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ADD a staff member to care team
app.post('/api/patients/:id/team', auth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No DB' });
  try {
    const { staff_id, role } = req.body;
    const r = await pool.query(
      `INSERT INTO patient_care_team(patient_id, staff_id, role)
       VALUES($1, $2, $3)
       ON CONFLICT(patient_id, staff_id) DO UPDATE SET role=$3
       RETURNING *`,
      [req.params.id, staff_id, role]
    );
    // Also update primary doctor_id/nurse_id on patients table for backwards compat
    if (role === 'Doctor') {
      await pool.query('UPDATE patients SET doctor_id=$1 WHERE id=$2', [staff_id, req.params.id]).catch(()=>{});
    } else if (role === 'Nurse') {
      await pool.query('UPDATE patients SET nurse_id=$1 WHERE id=$2', [staff_id, req.params.id]).catch(()=>{});
    }
    // Fetch staff name for socket emit
    const staffRow = await pool.query('SELECT name, role FROM staff WHERE id=$1', [staff_id]);
    io.emit('care_team:update', { patientId: req.params.id, action: 'add', staffId: String(staff_id), staffName: staffRow.rows[0]?.name, role });
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// REMOVE a staff member from care team
app.delete('/api/patients/:id/team/:staffId', auth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No DB' });
  try {
    await pool.query(
      'DELETE FROM patient_care_team WHERE patient_id=$1 AND staff_id=$2',
      [req.params.id, req.params.staffId]
    );
    io.emit('care_team:update', { patientId: req.params.id, action: 'remove', staffId: req.params.staffId });
    res.json({ ok: true });
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

    // Log audit
    logAudit(req.user.id, req.user.name, req.user.role, `Recorded vitals for patient #${pid}`, 'vitals', String(r.rows[0].id), { bp: `${b.bp_sys}/${b.bp_dia}`, spo2: b.spo2, pulse: b.pulse }, req.ip);

    // Fetch patient name once — used for both alerts and notification
    const ptRow = await pool.query('SELECT name FROM patients WHERE id=$1', [pid]).catch(() => ({ rows: [] }));
    const patientName = ptRow.rows[0]?.name || '';

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
      for (const a of alerts) {
        try {
          const ar = await pool.query(
            'INSERT INTO alerts(patient_id,type,title,message) VALUES($1,$2,$3,$4) RETURNING *',
            [pid, a.type, a.title, a.message]
          );
          savedAlerts.push({ ...ar.rows[0], patient_name: patientName });
        } catch(alertErr) {
          console.error('Alert INSERT failed:', alertErr.message);
          // Still emit with a temp id so real-time works even if DB insert fails
          savedAlerts.push({ id: Date.now(), patient_id: pid, type: a.type, title: a.title, message: a.message, patient_name: patientName, created_at: new Date().toISOString() });
        }
      }
      io.emit('alert:new', { patientId: String(pid), patientName, alerts: savedAlerts });
    }

    // Always emit notification for new vitals entry (nurse → doctor)
    io.emit('notification:new', {
      role: 'Doctor',
      title: `New Vitals: ${req.user.name}`,
      body: `${patientName || 'Patient #'+pid} — BP ${sbp}/${dbp}, SpO2 ${spo2}%`,
      time: new Date().toISOString(),
      patientId: String(pid),
      patientName,
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
    logAudit(req.user.id, req.user.name, req.user.role, `Prescribed ${b.drug} ${b.dose} for patient #${pid}`, 'prescription', String(r.rows[0].id), null, req.ip);
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
    // Ensure columns exist (idempotent migration)
    await pool.query(`
      ALTER TABLE lab_orders ADD COLUMN IF NOT EXISTS result_status TEXT DEFAULT '';
      ALTER TABLE lab_orders ADD COLUMN IF NOT EXISTS report_url TEXT;
      ALTER TABLE lab_orders ADD COLUMN IF NOT EXISTS report_name TEXT;
    `).catch(() => {}); // ignore if already exists

    const status = req.body.status || 'Result Available';
    const result = req.body.result !== undefined ? req.body.result : null;
    const result_status = req.body.result_status || req.body.resultStatus || '';
    const report_url = req.body.report_url || null;
    const report_name = req.body.report_name || null;

    const r = await pool.query(
      `UPDATE lab_orders SET result=$1, status=$2, result_status=$3, report_url=$4, report_name=$5
       WHERE id=$6 RETURNING *`,
      [result, status, result_status, report_url, report_name, req.params.id]
    );
    if (!r.rows[0]) return res.status(404).json({ error: 'Lab order not found' });

    // Fetch patient info for the socket emit
    const labRow = r.rows[0];
    const ptRow = await pool.query('SELECT name FROM patients WHERE id=$1', [labRow.patient_id]).catch(() => ({ rows: [] }));
    const patientName = ptRow.rows[0]?.name || '';

    const emitData = {
      ...labRow,
      patient_name: patientName,
      ordered_by_name: req.user.name,
    };
    io.emit('labs:result', emitData);
    logAudit(req.user.id, req.user.name, req.user.role, `Submitted lab result for ${labRow.test_name||'test'} — ${result_status}`, 'lab_order', req.params.id, null, req.ip);
    res.json(labRow);
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
    console.log(`[alerts] GET returned ${r.rows.length} rows`);
    res.json(r.rows);
  } catch (e) {
    console.error('[alerts] GET error:', e.message);
    res.status(500).json({ error: e.message });
  }
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

// ── NURSING NOTES ─────────────────────────────────────────────────────────────
app.get('/api/notes/nursing/:pid', auth, async (req, res) => {
  if (!pool) return res.json([]);
  try {
    const r = await pool.query(
      `SELECT n.*,s.name as written_by_name FROM nursing_notes n
       LEFT JOIN staff s ON s.id=n.written_by_id
       WHERE n.patient_id=$1 ORDER BY n.created_at DESC`,
      [req.params.pid]
    );
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/notes/nursing/:pid', auth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No DB' });
  try {
    const r = await pool.query(
      'INSERT INTO nursing_notes(patient_id,note,written_by_id) VALUES($1,$2,$3) RETURNING *',
      [req.params.pid, req.body.note||'', req.user.id]
    );
    logAudit(req.user.id, req.user.name, req.user.role, `Added nursing note for patient #${req.params.pid}`, 'nursing_note', String(r.rows[0].id), null, req.ip);
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── VACCINATIONS ──────────────────────────────────────────────────────────────
app.get('/api/vaccinations/:pid', auth, async (req, res) => {
  if (!pool) return res.json([]);
  try {
    const r = await pool.query(
      `SELECT v.*,s.name as given_by_name FROM vaccinations v
       LEFT JOIN staff s ON s.id=v.given_by_id
       WHERE v.patient_id=$1 ORDER BY v.created_at DESC`,
      [req.params.pid]
    );
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/vaccinations/:pid', auth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No DB' });
  const b = req.body;
  try {
    const r = await pool.query(
      `INSERT INTO vaccinations(patient_id,name,dose,dose_number,route,date_administered,next_due_date,notes,given_by_id)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [req.params.pid,b.name,b.dose||'',b.dose_number||'',b.route||'IM',
       b.date_administered||null,b.next_due_date||null,b.notes||'',req.user.id]
    );
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── FACILITY (Beds + Insurance) ───────────────────────────────────────────────
app.post('/api/facility/beds', auth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No DB' });
  try {
    const r = await pool.query(
      'INSERT INTO facility_beds(bed_id,ward,type) VALUES($1,$2,$3) ON CONFLICT(bed_id) DO UPDATE SET ward=$2,type=$3 RETURNING *',
      [req.body.bed_id, req.body.ward||'A', req.body.type||'General']
    );
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/facility/beds/:bedId', auth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No DB' });
  try {
    await pool.query('DELETE FROM facility_beds WHERE bed_id=$1', [req.params.bedId]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/facility/insurance', auth, async (req, res) => {
  if (!pool) return res.json([]);
  try {
    const r = await pool.query('SELECT * FROM facility_insurance ORDER BY name');
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/facility/insurance', auth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No DB' });
  const b = req.body;
  try {
    const r = await pool.query(
      'INSERT INTO facility_insurance(name,policy_types,contact,notes) VALUES($1,$2,$3,$4) RETURNING *',
      [b.name, b.policy_types||'', b.contact||'', b.notes||'']
    );
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/facility/insurance/:id', auth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No DB' });
  try {
    await pool.query('DELETE FROM facility_insurance WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
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

// ── BILLING ───────────────────────────────────────────────────────────────────
app.get('/api/bills', auth, async (req, res) => {
  if (!pool) return res.json([]);
  try {
    const r = await pool.query('SELECT * FROM bills ORDER BY generated_at DESC');
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/bills/:pid', auth, async (req, res) => {
  if (!pool) return res.json([]);
  try {
    const r = await pool.query('SELECT * FROM bills WHERE patient_id=$1 ORDER BY generated_at DESC', [req.params.pid]);
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/bills', auth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No DB' });
  const b = req.body;
  try {
    const r = await pool.query(
      `INSERT INTO bills(patient_id,ehr_id,patient_name,items,gross,discount,advance,insurance_deduction,net,
        insurance_company,insurance_policy,insurance_claim,locked,generated_by_id)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING *`,
      [b.patient_id,b.ehr_id,b.patient_name,JSON.stringify(b.items||[]),
       b.gross||0,b.discount||0,b.advance||0,b.insurance_deduction||0,b.net||0,
       b.insurance_company||null,b.insurance_policy||null,b.insurance_claim||null,
       b.locked||false,req.user.id]
    );
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/bills/:id', auth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No DB' });
  const b = req.body;
  try {
    const r = await pool.query(
      `UPDATE bills SET items=$1,gross=$2,discount=$3,advance=$4,insurance_deduction=$5,net=$6,
        insurance_company=$7,insurance_policy=$8,insurance_claim=$9,locked=$10,updated_at=NOW()
       WHERE id=$11 RETURNING *`,
      [JSON.stringify(b.items||[]),b.gross||0,b.discount||0,b.advance||0,b.insurance_deduction||0,b.net||0,
       b.insurance_company||null,b.insurance_policy||null,b.insurance_claim||null,b.locked||false,req.params.id]
    );
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── AUDIT LOG ─────────────────────────────────────────────────────────────────
app.get('/api/audit', auth, async (req, res) => {
  if (!pool) return res.json([]);
  try {
    const r = await pool.query('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 200');
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Helper to log audit events (called internally)
async function logAudit(userId, userName, userRole, action, entityType, entityId, details, ip) {
  if (!pool) return;
  pool.query(
    'INSERT INTO audit_log(user_id,user_name,user_role,action,entity_type,entity_id,details,ip_address) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',
    [userId, userName, userRole, action, entityType||null, entityId||null, details ? JSON.stringify(details) : null, ip||null]
  ).catch(() => {});
}

// ── INVENTORY ─────────────────────────────────────────────────────────────────
app.get('/api/inventory', auth, async (req, res) => {
  if (!pool) return res.json([]);
  try {
    const r = await pool.query('SELECT * FROM inventory ORDER BY category, name');
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/inventory', auth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No DB' });
  const b = req.body;
  try {
    const r = await pool.query(
      `INSERT INTO inventory(name,category,unit,quantity,min_quantity,unit_cost,supplier,expiry_date,updated_by_id)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [b.name,b.category||'General',b.unit||'units',b.quantity||0,b.min_quantity||10,
       b.unit_cost||0,b.supplier||null,b.expiry_date||null,req.user.id]
    );
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/inventory/:id', auth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No DB' });
  const b = req.body;
  try {
    const r = await pool.query(
      `UPDATE inventory SET name=$1,category=$2,unit=$3,quantity=$4,min_quantity=$5,
        unit_cost=$6,supplier=$7,expiry_date=$8,updated_by_id=$9,updated_at=NOW()
       WHERE id=$10 RETURNING *`,
      [b.name,b.category||'General',b.unit||'units',b.quantity||0,b.min_quantity||10,
       b.unit_cost||0,b.supplier||null,b.expiry_date||null,req.user.id,req.params.id]
    );
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/inventory/:id', auth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No DB' });
  try {
    await pool.query('DELETE FROM inventory WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Run DB migrations on startup
if (pool) {
  pool.query(`
    ALTER TABLE lab_orders ADD COLUMN IF NOT EXISTS result_status TEXT DEFAULT '';
    ALTER TABLE lab_orders ADD COLUMN IF NOT EXISTS report_url TEXT;
    ALTER TABLE lab_orders ADD COLUMN IF NOT EXISTS report_name TEXT;
  `).then(() => console.log('DB migration: lab_orders columns ensured'))
    .catch(e => console.warn('DB migration warning:', e.message));

  // Create new tables if not exists
  pool.query(`
    CREATE TABLE IF NOT EXISTS bills (
      id SERIAL PRIMARY KEY, patient_id INTEGER REFERENCES patients(id),
      ehr_id TEXT, patient_name TEXT, items JSONB DEFAULT '[]',
      gross NUMERIC DEFAULT 0, discount NUMERIC DEFAULT 0, advance NUMERIC DEFAULT 0,
      insurance_deduction NUMERIC DEFAULT 0, net NUMERIC DEFAULT 0,
      insurance_company TEXT, insurance_policy TEXT, insurance_claim TEXT,
      locked BOOLEAN DEFAULT false, generated_by_id INTEGER REFERENCES staff(id),
      generated_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS audit_log (
      id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES staff(id),
      user_name TEXT, user_role TEXT, action TEXT NOT NULL,
      entity_type TEXT, entity_id TEXT, details JSONB, ip_address TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS inventory (
      id SERIAL PRIMARY KEY, name TEXT NOT NULL, category TEXT DEFAULT 'General',
      unit TEXT DEFAULT 'units', quantity INTEGER DEFAULT 0, min_quantity INTEGER DEFAULT 10,
      unit_cost NUMERIC DEFAULT 0, supplier TEXT, expiry_date DATE,
      updated_by_id INTEGER REFERENCES staff(id), updated_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS patient_care_team (
      id SERIAL PRIMARY KEY, patient_id INTEGER REFERENCES patients(id) ON DELETE CASCADE,
      staff_id INTEGER REFERENCES staff(id) ON DELETE CASCADE, role TEXT NOT NULL,
      added_at TIMESTAMPTZ DEFAULT NOW(), UNIQUE(patient_id, staff_id)
    );
    CREATE TABLE IF NOT EXISTS nursing_notes (
      id SERIAL PRIMARY KEY, patient_id INTEGER REFERENCES patients(id),
      note TEXT NOT NULL, written_by_id INTEGER REFERENCES staff(id),
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS vaccinations (
      id SERIAL PRIMARY KEY, patient_id INTEGER REFERENCES patients(id),
      name TEXT NOT NULL, dose TEXT DEFAULT '', dose_number TEXT DEFAULT '',
      route TEXT DEFAULT 'IM', date_administered DATE, next_due_date DATE,
      notes TEXT DEFAULT '', given_by_id INTEGER REFERENCES staff(id),
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS facility_beds (
      id SERIAL PRIMARY KEY, bed_id TEXT UNIQUE NOT NULL,
      ward TEXT DEFAULT 'A', type TEXT DEFAULT 'General',
      status TEXT DEFAULT 'available', created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS facility_insurance (
      id SERIAL PRIMARY KEY, name TEXT NOT NULL,
      policy_types TEXT DEFAULT '', contact TEXT DEFAULT '',
      notes TEXT DEFAULT '', created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS network_dms (
      id SERIAL PRIMARY KEY, sender_id INTEGER REFERENCES staff(id),
      receiver_id INTEGER REFERENCES staff(id), text TEXT NOT NULL,
      read BOOLEAN DEFAULT false, created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS alerts (
      id SERIAL PRIMARY KEY,
      patient_id INTEGER REFERENCES patients(id),
      type TEXT DEFAULT 'info',
      title TEXT,
      message TEXT,
      acknowledged_by INTEGER REFERENCES staff(id),
      acknowledged_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS consult_notes (
      id SERIAL PRIMARY KEY,
      patient_id INTEGER REFERENCES patients(id),
      subjective TEXT DEFAULT '',
      objective TEXT DEFAULT '',
      assessment TEXT DEFAULT '',
      plan TEXT DEFAULT '',
      created_by_id INTEGER REFERENCES staff(id),
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS mar (
      id SERIAL PRIMARY KEY,
      prescription_id INTEGER REFERENCES prescriptions(id),
      patient_id INTEGER REFERENCES patients(id),
      status TEXT,
      given_by_id INTEGER REFERENCES staff(id),
      given_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS chat_messages (
      id SERIAL PRIMARY KEY,
      patient_id INTEGER REFERENCES patients(id),
      sender_id INTEGER REFERENCES staff(id),
      message TEXT NOT NULL,
      sent_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS network_posts (
      id SERIAL PRIMARY KEY,
      author_id INTEGER REFERENCES staff(id),
      text TEXT NOT NULL,
      tag TEXT DEFAULT 'Discussion',
      case_label TEXT,
      case_history JSONB,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS network_post_likes (
      post_id INTEGER REFERENCES network_posts(id) ON DELETE CASCADE,
      staff_id INTEGER REFERENCES staff(id),
      PRIMARY KEY(post_id, staff_id)
    );
    CREATE TABLE IF NOT EXISTS network_post_replies (
      id SERIAL PRIMARY KEY,
      post_id INTEGER REFERENCES network_posts(id) ON DELETE CASCADE,
      author_id INTEGER REFERENCES staff(id),
      text TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS opd_queue (
      id SERIAL PRIMARY KEY,
      patient_id INTEGER REFERENCES patients(id),
      token_no INTEGER,
      status TEXT DEFAULT 'Waiting',
      doctor_id INTEGER REFERENCES staff(id),
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    ALTER TABLE lab_orders ADD COLUMN IF NOT EXISTS result_status TEXT DEFAULT '';
    ALTER TABLE lab_orders ADD COLUMN IF NOT EXISTS report_url TEXT;
    ALTER TABLE lab_orders ADD COLUMN IF NOT EXISTS report_name TEXT;
    CREATE TABLE IF NOT EXISTS patient_accounts (
      id SERIAL PRIMARY KEY,
      patient_id INTEGER REFERENCES patients(id) ON DELETE CASCADE,
      phone TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `).then(() => console.log('DB migration: new tables ensured'))
    .catch(e => console.warn('DB migration warning:', e.message));
}

// On startup: auto-create patient accounts for all existing patients with phone numbers
if (pool) {
  pool.query("SELECT id, phone FROM patients WHERE phone IS NOT NULL AND phone != '' AND phone != 'null'")
    .then(async patients => {
      const defaultHash = await bcrypt.hash('password', 10);
      let created = 0;
      for (const p of patients.rows) {
        try {
          const r = await pool.query(
            `INSERT INTO patient_accounts(patient_id, phone, password_hash)
             VALUES($1, $2, $3) ON CONFLICT(phone) DO NOTHING`,
            [p.id, p.phone.trim().replace(/\D/g, '').slice(-10), defaultHash]
          );
          if (r.rowCount > 0) created++;
        } catch(e) {}
      }
      if (created > 0) console.log(`[startup] Created ${created} patient accounts`);
    })
    .catch(e => console.warn('[startup] patient accounts sync:', e.message));
}

server.listen(PORT, () => console.log(`Vyasa backend running on port ${PORT}`));
