require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Configuração da conexão com o PostgreSQL no Render
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

app.use(express.json());
app.use(express.static(path.join(__dirname)));

// Inicializa as tabelas no Banco de Dados
async function initDb() {
  try {
    const client = await pool.connect();
    
    // Tabela de Médicos
    await client.query(`
      CREATE TABLE IF NOT EXISTS doctors (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        crm VARCHAR(20) UNIQUE NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(100) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Tabela de Pacientes
    await client.query(`
      CREATE TABLE IF NOT EXISTS patients (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        cpf VARCHAR(14) UNIQUE NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(100) NOT NULL,
        ticket_number VARCHAR(10),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Tabela de Plantões / Escalas
    await client.query(`
      CREATE TABLE IF NOT EXISTS shifts (
        id SERIAL PRIMARY KEY,
        doctor_id INT REFERENCES doctors(id),
        hospital_name VARCHAR(100) NOT NULL,
        sector VARCHAR(50) NOT NULL,
        start_time TIMESTAMP NOT NULL,
        end_time TIMESTAMP NOT NULL,
        status VARCHAR(20) DEFAULT 'agendado', -- agendado, trocando, concluido
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    console.log('✅ Banco de dados PostgreSQL conectado e tabelas verificadas/criadas.');
    client.release();
  } catch (err) {
    console.error('❌ Erro ao conectar ou inicializar o banco de dados:', err);
  }
}

initDb();

// --- ROTAS DA API ---

// Cadastro de Médico
app.post('/api/register-doctor', async (req, res) => {
  const { name, crm, email, password } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO doctors (name, crm, email, password) VALUES ($1, $2, $3, $4) RETURNING id, name, email',
      [name, crm, email, password]
    );
    res.status(201).json({ success: true, doctor: result.rows[0] });
  } catch (error) {
    res.status(400).json({ success: false, message: 'Erro ao cadastrar médico: E-mail ou CRM já em uso.' });
  }
});

// Login de Médico
app.post('/api/login-doctor', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query(
      'SELECT * FROM doctors WHERE email = $1 AND password = $2',
      [email, password]
    );
    if (result.rows.length > 0) {
      res.json({ success: true, redirect: '/dashboard-medico.html', user: result.rows[0] });
    } else {
      res.status(401).json({ success: false, message: 'E-mail ou senha incorretos.' });
    }
  } catch (error) {
    res.status(500).json({ success: false, message: 'Erro interno no servidor.' });
  }
});

// Cadastro de Paciente
app.post('/api/register-patient', async (req, res) => {
  const { name, cpf, email, password } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO patients (name, cpf, email, password) VALUES ($1, $2, $3, $4) RETURNING id, name, email',
      [name, cpf, email, password]
    );
    res.status(201).json({ success: true, patient: result.rows[0] });
  } catch (error) {
    res.status(400).json({ success: false, message: 'Erro ao cadastrar paciente: E-mail ou CPF já em uso.' });
  }
});

// Login de Paciente
app.post('/api/login-patient', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query(
      'SELECT * FROM patients WHERE email = $1 AND password = $2',
      [email, password]
    );
    if (result.rows.length > 0) {
      res.json({ success: true, redirect: '/dashboard-paciente.html', user: result.rows[0] });
    } else {
      res.status(401).json({ success: false, message: 'E-mail ou senha incorretos.' });
    }
  } catch (error) {
    res.status(500).json({ success: false, message: 'Erro interno no servidor.' });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Servidor rodando na porta ${PORT}`);
});