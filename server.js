require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Configuração do Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Configuração do Banco de Dados PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && !process.env.DATABASE_URL.includes('localhost')
    ? { rejectUnauthorized: false }
    : false
});

// Teste de conexão com o banco de dados
pool.connect((err, client, release) => {
  if (err) {
    console.error('Erro ao conectar ao PostgreSQL:', err.stack);
  } else {
    console.log('Conectado ao PostgreSQL com sucesso!');
    release();
  }
});

// ==========================================
// ROTAS DE AUTENTICAÇÃO (MÉDICOS & PACIENTES)
// ==========================================

// Cadastro de Médico
app.post('/api/register/doctor', async (req, res) => {
  const { name, crm, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO doctors (name, crm, email, password_hash) VALUES ($1, $2, $3, $4) RETURNING id, name, crm, email',
      [name, crm, email, hashedPassword]
    );

    // Vincula o médico ao Hospital Santo Antônio por padrão no cadastro
    await pool.query(
      'INSERT INTO doctor_hospitals (doctor_id, hospital_id) VALUES ($1, 1) ON CONFLICT DO NOTHING',
      [result.rows[0].id]
    );

    res.status(201).json({ message: 'Médico cadastrado com sucesso!', doctor: result.rows[0] });
  } catch (err) {
    console.error(err);
    if (err.code === '23505') {
      return res.status(400).json({ error: 'CRM ou E-mail já cadastrado.' });
    }
    res.status(500).json({ error: 'Erro no servidor ao cadastrar médico.' });
  }
});

// Login de Médico
app.post('/api/login/doctor', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM doctors WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'E-mail ou senha incorretos.' });
    }

    const doctor = result.rows[0];
    const validPassword = await bcrypt.compare(password, doctor.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'E-mail ou senha incorretos.' });
    }

    res.json({
      message: 'Login realizado com sucesso!',
      user: { id: doctor.id, name: doctor.name, crm: doctor.crm, email: doctor.email }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro no servidor ao realizar login.' });
  }
});

// Cadastro de Paciente
app.post('/api/register/patient', async (req, res) => {
  const { name, cpf, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO patients (name, cpf, email, password_hash) VALUES ($1, $2, $3, $4) RETURNING id, name, cpf, email',
      [name, cpf, email, hashedPassword]
    );
    res.status(201).json({ message: 'Paciente cadastrado com sucesso!', patient: result.rows[0] });
  } catch (err) {
    console.error(err);
    if (err.code === '23505') {
      return res.status(400).json({ error: 'CPF ou E-mail já cadastrado.' });
    }
    res.status(500).json({ error: 'Erro no servidor ao cadastrar paciente.' });
  }
});

// Login de Paciente
app.post('/api/login/patient', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM patients WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'E-mail ou senha incorretos.' });
    }

    const patient = result.rows[0];
    const validPassword = await bcrypt.compare(password, patient.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'E-mail ou senha incorretos.' });
    }

    res.json({
      message: 'Login realizado com sucesso!',
      user: { id: patient.id, name: patient.name, cpf: patient.cpf, email: patient.email }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro no servidor ao realizar login.' });
  }
});

// ==========================================
// ROTAS SAAS: DASHBOARD DO MÉDICO
// ==========================================

// Lista de Hospitais disponíveis no sistema
app.get('/api/hospitals', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name FROM hospitals ORDER BY name ASC');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao buscar hospitais.' });
  }
});

// Dados para a "Visão Geral" do Médico
app.get('/api/doctor/overview', async (req, res) => {
  const { doctor_id, hospital_id } = req.query;

  if (!doctor_id || !hospital_id) {
    return res.status(400).json({ error: 'doctor_id e hospital_id são obrigatórios.' });
  }

  try {
    // 1. Busca o próximo plantão do médico logado
    const nextShiftQuery = await pool.query(
      `SELECT shift_date, start_time, end_time, sector 
       FROM shifts 
       WHERE doctor_id = $1 AND hospital_id = $2 AND shift_date >= CURRENT_DATE 
       ORDER BY shift_date ASC, start_time ASC LIMIT 1`,
      [doctor_id, hospital_id]
    );

    // 2. Total de horas confirmadas no mês atual
    const monthHoursQuery = await pool.query(
      `SELECT COUNT(*) * 12 as total_hours 
       FROM shifts 
       WHERE doctor_id = $1 AND hospital_id = $2 
       AND DATE_TRUNC('month', shift_date) = DATE_TRUNC('month', CURRENT_DATE)`,
      [doctor_id, hospital_id]
    );

    // 3. Quantidade de plantões abertos no hospital selecionado
    const openShiftsQuery = await pool.query(
      `SELECT COUNT(*) as open_count 
       FROM shifts 
       WHERE hospital_id = $1 AND doctor_id IS NULL AND shift_date >= CURRENT_DATE`,
      [hospital_id]
    );

    res.json({
      nextShift: nextShiftQuery.rows[0] || null,
      monthlyHours: monthHoursQuery.rows[0]?.total_hours || 0,
      openShiftsCount: openShiftsQuery.rows[0]?.open_count || 0
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao carregar dados da Visão Geral.' });
  }
});

// Dados da "Minha Escala" (Grade de Plantões Semanal)
app.get('/api/doctor/schedule', async (req, res) => {
  const { hospital_id } = req.query;

  if (!hospital_id) {
    return res.status(400).json({ error: 'hospital_id é obrigatório.' });
  }

  try {
    const result = await pool.query(
      `SELECT s.id, s.shift_date, s.start_time, s.end_time, s.sector, s.doctor_id, d.name as doctor_name
       FROM shifts s
       LEFT JOIN doctors d ON s.doctor_id = d.id
       WHERE s.hospital_id = $1
       ORDER BY s.shift_date ASC, s.start_time ASC`,
      [hospital_id]
    );

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao buscar escala de plantões.' });
  }
});

// Redirecionamento padrão para SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Inicialização do Servidor
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
