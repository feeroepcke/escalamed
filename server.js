const express = require('express');
const { Pool } = require('pg');
const path = require('path');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Configuração da conexão com o PostgreSQL
const isProduction = process.env.NODE_ENV === 'production' || process.env.DATABASE_URL?.includes('render.com');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: isProduction ? { rejectUnauthorized: false } : false
});

// Testar conexão com o PostgreSQL
pool.connect((err, client, release) => {
  if (err) {
    console.error('Erro ao conectar ao PostgreSQL:', err.message);
  } else {
    console.log('Conectado com sucesso ao banco de dados PostgreSQL.');
    release();
  }
});

// Criar tabelas se não existirem
const initDb = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS doctors (
        id SERIAL PRIMARY KEY,
        category TEXT,
        council TEXT,
        registry TEXT,
        cpf TEXT,
        email TEXT UNIQUE,
        password TEXT
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS patients (
        id SERIAL PRIMARY KEY,
        cpf TEXT UNIQUE,
        email TEXT,
        password TEXT
      );
    `);

    console.log('Tabelas verificadas/criadas com sucesso.');
  } catch (err) {
    console.error('Erro ao criar tabelas:', err.message);
  }
};

initDb();

// Rota de Cadastro de Médico
app.post('/api/register-doctor', async (req, res) => {
  const { category, council, registry, cpf, email, password } = req.body;
  const query = `
    INSERT INTO doctors (category, council, registry, cpf, email, password) 
    VALUES ($1, $2, $3, $4, $5, $6) 
    RETURNING id
  `;

  try {
    const result = await pool.query(query, [category, council, registry, cpf, email, password]);
    res.status(201).json({ message: 'Médico cadastrado com sucesso!', id: result.rows[0].id });
  } catch (err) {
    res.status(400).json({ error: 'E-mail já cadastrado ou dados inválidos.' });
  }
});

// Rota de Login de Médico
app.post('/api/login-doctor', async (req, res) => {
  const { email, password } = req.body;
  const query = `SELECT * FROM doctors WHERE email = $1 AND password = $2`;

  try {
    const result = await pool.query(query, [email, password]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'E-mail ou senha incorretos.' });
    }
    res.json({ message: 'Login bem-sucedido', user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Erro no servidor.' });
  }
});

// Rota de Cadastro de Paciente
app.post('/api/register-patient', async (req, res) => {
  const { cpf, email, password } = req.body;
  const query = `
    INSERT INTO patients (cpf, email, password) 
    VALUES ($1, $2, $3) 
    RETURNING id
  `;

  try {
    const result = await pool.query(query, [cpf, email, password]);
    res.status(201).json({ message: 'Paciente cadastrado com sucesso!', id: result.rows[0].id });
  } catch (err) {
    res.status(400).json({ error: 'CPF já cadastrado.' });
  }
});

// Rota de Login de Paciente
app.post('/api/login-patient', async (req, res) => {
  const { loginId, password } = req.body;
  const query = `SELECT * FROM patients WHERE (email = $1 OR cpf = $2) AND password = $3`;

  try {
    const result = await pool.query(query, [loginId, loginId, password]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Credenciais inválidas.' });
    }
    res.json({ message: 'Login bem-sucedido', user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Erro no servidor.' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});