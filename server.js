const express = require('express');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static('public'));

// Conexão com o PostgreSQL no Render
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// --- ROTAS DO MÉDICO ---

// Cadastro de Médico
app.post('/api/register-doctor', async (req, res) => {
  const { name, crm, email, password } = req.body;

  if (!name || !crm || !email || !password) {
    return res.status(400).json({ success: false, message: 'Preencha todos os campos obrigatórios.' });
  }

  const cleanEmail = email.toLowerCase().trim();
  const cleanCrm = crm.trim();

  try {
    // Verifica se já existe e-mail ou CRM cadastrado
    const checkUser = await pool.query(
      'SELECT id FROM doctors WHERE email = $1 OR crm = $2',
      [cleanEmail, cleanCrm]
    );

    if (checkUser.rows.length > 0) {
      return res.status(400).json({ success: false, message: 'E-mail ou CRM já cadastrado.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      'INSERT INTO doctors (name, crm, email, password_hash) VALUES ($1, $2, $3, $4)',
      [name, cleanCrm, cleanEmail, hashedPassword]
    );

    res.json({ success: true, message: 'Médico cadastrado com sucesso!' });
  } catch (err) {
    console.error('Erro no cadastro de médico:', err);
    res.status(500).json({ success: false, message: 'Erro interno no servidor ao cadastrar médico.' });
  }
});

// Login de Médico
app.post('/api/login-doctor', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Informe e-mail e senha.' });
  }

  try {
    const cleanEmail = email.toLowerCase().trim();
    const result = await pool.query('SELECT * FROM doctors WHERE email = $1', [cleanEmail]);
    
    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, message: 'E-mail ou senha incorretos.' });
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);

    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'E-mail ou senha incorretos.' });
    }

    res.json({
      success: true,
      redirect: '/dashboard-medico.html',
      user: { id: user.id, name: user.name, email: user.email }
    });
  } catch (err) {
    console.error('Erro no login de médico:', err);
    res.status(500).json({ success: false, message: 'Erro interno no servidor ao realizar login.' });
  }
});

// --- ROTAS DO PACIENTE ---

// Cadastro de Paciente
app.post('/api/register-patient', async (req, res) => {
  const { name, cpf, email, password } = req.body;

  if (!name || !cpf || !email || !password) {
    return res.status(400).json({ success: false, message: 'Preencha todos os campos obrigatórios.' });
  }

  const cleanCpf = cpf.replace(/\D/g, ''); // Remove pontos e hífens do CPF
  const cleanEmail = email.toLowerCase().trim();

  try {
    // Verifica se já existe e-mail ou CPF no banco
    const checkUser = await pool.query(
      'SELECT id FROM patients WHERE email = $1 OR cpf = $2',
      [cleanEmail, cleanCpf]
    );

    if (checkUser.rows.length > 0) {
      return res.status(400).json({ success: false, message: 'E-mail ou CPF já em uso.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      'INSERT INTO patients (name, cpf, email, password_hash) VALUES ($1, $2, $3, $4)',
      [name, cleanCpf, cleanEmail, hashedPassword]
    );

    res.json({ success: true, message: 'Paciente cadastrado com sucesso!' });
  } catch (err) {
    console.error('Erro no cadastro de paciente:', err);
    res.status(500).json({ success: false, message: 'Erro interno no servidor ao cadastrar paciente.' });
  }
});

// Login de Paciente
app.post('/api/login-patient', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Informe e-mail e senha.' });
  }

  try {
    const cleanEmail = email.toLowerCase().trim();
    const result = await pool.query('SELECT * FROM patients WHERE email = $1', [cleanEmail]);

    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, message: 'E-mail ou senha incorretos.' });
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);

    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'E-mail ou senha incorretos.' });
    }

    res.json({
      success: true,
      redirect: '/dashboard-paciente.html',
      user: { id: user.id, name: user.name, email: user.email }
    });
  } catch (err) {
    console.error('Erro no login de paciente:', err);
    res.status(500).json({ success: false, message: 'Erro interno no servidor ao realizar login.' });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
