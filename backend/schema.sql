-- Run this in your Render Postgres database

CREATE TABLE IF NOT EXISTS staff (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  role TEXT NOT NULL,
  department TEXT DEFAULT '',
  specialty TEXT DEFAULT '',
  emp_id TEXT DEFAULT '',
  email TEXT UNIQUE,
  password_hash TEXT NOT NULL,
  available BOOLEAN DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS patients (
  id SERIAL PRIMARY KEY,
  ehr_id TEXT UNIQUE,
  name TEXT NOT NULL,
  age INTEGER,
  gender TEXT,
  phone TEXT,
  diagnosis TEXT DEFAULT '',
  icd_code TEXT DEFAULT 'Z00',
  bed TEXT,
  doctor_id INTEGER REFERENCES staff(id),
  nurse_id INTEGER REFERENCES staff(id),
  admission_type TEXT DEFAULT 'OPD Consultation',
  chief_complaint TEXT DEFAULT '',
  allergies TEXT DEFAULT 'None Known',
  blood_group TEXT,
  status TEXT DEFAULT 'OPD',
  diag_type TEXT DEFAULT 'Provisional',
  height_cm NUMERIC,
  weight_kg NUMERIC,
  bmi NUMERIC,
  address TEXT,
  pincode TEXT,
  chronic_diseases TEXT,
  insurance_company TEXT,
  insurance_policy TEXT,
  insurance_member TEXT,
  insurance_type TEXT,
  discharge_condition TEXT,
  discharge_time TIMESTAMPTZ,
  admit_time TIMESTAMPTZ DEFAULT NOW(),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Auto-generate EHR ID
CREATE OR REPLACE FUNCTION set_ehr_id() RETURNS TRIGGER AS $$
BEGIN
  IF NEW.ehr_id IS NULL THEN
    NEW.ehr_id := 'EHR-' || LPAD(NEW.id::TEXT, 5, '0');
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_ehr_id ON patients;
CREATE TRIGGER trg_ehr_id BEFORE INSERT ON patients FOR EACH ROW EXECUTE FUNCTION set_ehr_id();

CREATE TABLE IF NOT EXISTS vitals (
  id SERIAL PRIMARY KEY,
  patient_id INTEGER REFERENCES patients(id),
  bp_sys INTEGER, bp_dia INTEGER, pulse INTEGER, spo2 INTEGER,
  temperature NUMERIC, resp_rate INTEGER, gcs INTEGER DEFAULT 15,
  urine_output INTEGER DEFAULT 40, blood_glucose INTEGER DEFAULT 100,
  drain_output INTEGER DEFAULT 0, pain_score INTEGER DEFAULT 0,
  notes TEXT DEFAULT '',
  recorded_by_id INTEGER REFERENCES staff(id),
  recorded_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS prescriptions (
  id SERIAL PRIMARY KEY,
  patient_id INTEGER REFERENCES patients(id),
  drug TEXT NOT NULL,
  dose TEXT DEFAULT '',
  route TEXT DEFAULT 'Oral',
  frequency TEXT DEFAULT '',
  duration TEXT DEFAULT '',
  instructions TEXT DEFAULT '',
  prescribed_by_id INTEGER REFERENCES staff(id),
  status TEXT DEFAULT 'active',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS lab_orders (
  id SERIAL PRIMARY KEY,
  patient_id INTEGER REFERENCES patients(id),
  test_name TEXT NOT NULL,
  category TEXT DEFAULT '',
  priority TEXT DEFAULT 'Routine',
  status TEXT DEFAULT 'Pending',
  result TEXT,
  ordered_by_id INTEGER REFERENCES staff(id),
  created_at TIMESTAMPTZ DEFAULT NOW()
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

CREATE TABLE IF NOT EXISTS opd_queue (
  id SERIAL PRIMARY KEY,
  patient_id INTEGER REFERENCES patients(id),
  token_no INTEGER,
  status TEXT DEFAULT 'Waiting',
  doctor_id INTEGER REFERENCES staff(id),
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

-- Seed default staff
INSERT INTO staff(name,role,department,specialty,emp_id,email,password_hash) VALUES
  ('Dr. Arjun Mehta','Doctor','Cardiology','Cardiology','D-001','arjun@nurselink.in', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi'),
  ('Dr. Nilanjan Roy','Doctor','General Medicine','General Medicine','D-002','nilanjan@nurselink.in', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi'),
  ('Dr. Sunita Rao','Doctor','Neurology','Neurology','D-003','sunita@nurselink.in', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi'),
  ('Nurse Priya','Nurse','Ward A','','N-001','priya@nurselink.in', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi'),
  ('Admin User','Admin','Administration','','A-001','admin@nurselink.in', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi')
ON CONFLICT(email) DO NOTHING;
