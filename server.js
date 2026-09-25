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

// Helper interno para validar senhas (suporta Hash Bcrypt e Texto Puro)
async function validarSenha(senhaDigitada, senhaBanco) {
  if (!senhaBanco) return false;
  if (senhaBanco.startsWith('$2a$') || senhaBanco.startsWith('$2b$') || senhaBanco.startsWith('$2y$')) {
    return await bcrypt.compare(senhaDigitada, senhaBanco);
  }
  return senhaDigitada === senhaBanco;
}

// ==========================================
// ROTAS DE AUTENTICAÇÃO (MÉDICOS, PACIENTES & GESTORES)
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

    await pool.query(
      'INSERT INTO doctor_hospitals (doctor_id, hospital_id) VALUES ($1, 1) ON CONFLICT DO NOTHING',
      [result.rows[0].id]
    );

    res.status(201).json({ message: 'Médico cadastrado com sucesso!', doctor: result.rows[0] });
  } catch (err) {
    console.error('Erro no cadastro do médico:', err);
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
    const senhaBanco = doctor.password_hash || doctor.senha || doctor.password;
    const validPassword = await validarSenha(password, senhaBanco);

    if (!validPassword) {
      return res.status(401).json({ error: 'E-mail ou senha incorretos.' });
    }

    res.json({
      message: 'Login realizado com sucesso!',
      user: { id: doctor.id, name: doctor.name || doctor.nome, crm: doctor.crm, email: doctor.email }
    });
  } catch (err) {
    console.error('Erro no login do médico:', err);
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
    console.error('Erro no cadastro do paciente:', err);
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
    const senhaBanco = patient.password_hash || patient.senha || patient.password;
    const validPassword = await validarSenha(password, senhaBanco);

    if (!validPassword) {
      return res.status(401).json({ error: 'E-mail ou senha incorretos.' });
    }

    res.json({
      message: 'Login realizado com sucesso!',
      user: { id: patient.id, name: patient.name || patient.nome, cpf: patient.cpf, email: patient.email }
    });
  } catch (err) {
    console.error('Erro no login do paciente:', err);
    res.status(500).json({ error: 'Erro no servidor ao realizar login.' });
  }
});

// Cadastro de Gestor (Com suporte a tabelas com password_hash ou senha)
app.post('/api/register/manager', async (req, res) => {
  const { name, hospital, role, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    let result;
    
    try {
      result = await pool.query(
        'INSERT INTO managers (name, hospital, role, email, password_hash) VALUES ($1, $2, $3, $4, $5) RETURNING id, name, hospital, role, email',
        [name, hospital, role, email, hashedPassword]
      );
    } catch (dbErr) {
      // Fallback para caso a coluna da tabela 'managers' seja 'senha' ou 'nome'
      if (dbErr.code === '42703') { // Coluna não existe
        result = await pool.query(
          'INSERT INTO managers (nome, hospital, cargo, email, senha) VALUES ($1, $2, $3, $4, $5) RETURNING id, nome as name, hospital, cargo as role, email',
          [name, hospital, role, email, hashedPassword]
        );
      } else {
        throw dbErr;
      }
    }

    res.status(201).json({ message: 'Gestor cadastrado com sucesso!', user: result.rows[0] });
  } catch (err) {
    console.error('Erro no cadastro do gestor:', err);
    if (err.code === '23505') {
      return res.status(400).json({ error: 'E-mail já cadastrado.' });
    }
    res.status(500).json({ error: 'Erro no servidor ao cadastrar gestor.' });
  }
});

// Login de Gestor
app.post('/api/login/manager', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM managers WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'E-mail ou senha incorretos.' });
    }

    const manager = result.rows[0];
    const senhaBanco = manager.password_hash || manager.senha || manager.password;
    const validPassword = await validarSenha(password, senhaBanco);

    if (!validPassword) {
      return res.status(401).json({ error: 'E-mail ou senha incorretos.' });
    }

    res.json({
      message: 'Login realizado com sucesso!',
      user: {
        id: manager.id,
        name: manager.name || manager.nome,
        hospital: manager.hospital,
        role: manager.role || manager.cargo,
        email: manager.email,
        type: 'manager'
      }
    });
  } catch (err) {
    console.error('Erro no login do gestor:', err);
    res.status(500).json({ error: 'Erro no servidor ao realizar login.' });
  }
});

// ==========================================
// ROTAS SAAS: GESTÃO DE PLANTÕES (GESTOR)
// ==========================================

// Criar novo plantão
app.post('/api/manager/shifts', async (req, res) => {
  const { hospital_id, shift_date, start_time, end_time, sector, specialty, doctor_id } = req.body;

  if (!hospital_id || !shift_date || !start_time || !end_time || !sector) {
    return res.status(400).json({ error: 'Campos obrigatórios ausentes.' });
  }

  try {
    const result = await pool.query(
      `INSERT INTO shifts (hospital_id, shift_date, start_time, end_time, sector, specialty, doctor_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [hospital_id, shift_date, start_time, end_time, sector, specialty || null, doctor_id || null]
    );

    res.status(201).json({ message: 'Plantão criado com sucesso!', shift: result.rows[0] });
  } catch (err) {
    console.error('Erro ao cadastrar plantão:', err);
    res.status(500).json({ error: 'Erro no servidor ao criar plantão.' });
  }
});

// Listar plantões do hospital para o gestor
app.get('/api/manager/shifts', async (req, res) => {
  const { hospital_id } = req.query;

  if (!hospital_id) {
    return res.status(400).json({ error: 'hospital_id é obrigatório.' });
  }

  try {
    const result = await pool.query(
      `SELECT s.id, s.shift_date, s.start_time, s.end_time, s.sector, s.specialty, s.doctor_id, d.name as doctor_name
       FROM shifts s
       LEFT JOIN doctors d ON s.doctor_id = d.id
       WHERE s.hospital_id = $1
       ORDER BY s.shift_date DESC, s.start_time ASC`,
      [hospital_id]
    );

    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar plantões para o gestor:', err);
    res.status(500).json({ error: 'Erro ao carregar lista de plantões.' });
  }
});

// Vincular / Desvincular médico de um plantão
app.patch('/api/manager/shifts/:id/assign', async (req, res) => {
  const { id } = req.params;
  const { doctor_id } = req.body;

  try {
    const result = await pool.query(
      `UPDATE shifts SET doctor_id = $1 WHERE id = $2 RETURNING *`,
      [doctor_id || null, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Plantão não encontrado.' });
    }

    res.json({ message: 'Escala atualizada com sucesso!', shift: result.rows[0] });
  } catch (err) {
    console.error('Erro ao atualizar médico do plantão:', err);
    res.status(500).json({ error: 'Erro no servidor ao atualizar plantão.' });
  }
});

// Deletar um plantão
app.delete('/api/manager/shifts/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query('DELETE FROM shifts WHERE id = $1 RETURNING id', [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Plantão não encontrado.' });
    }

    res.json({ message: 'Plantão excluído com sucesso!' });
  } catch (err) {
    console.error('Erro ao deletar plantão:', err);
    res.status(500).json({ error: 'Erro no servidor ao excluir plantão.' });
  }
});

// ==========================================
// ROTAS SAAS: DASHBOARD DO MÉDICO
// ==========================================

app.get('/api/hospitals', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name FROM hospitals ORDER BY name ASC');
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar hospitais:', err);
    res.status(500).json({ error: 'Erro ao buscar hospitais.' });
  }
});

app.get('/api/doctor/overview', async (req, res) => {
  const { doctor_id, hospital_id } = req.query;

  if (!doctor_id || !hospital_id) {
    return res.status(400).json({ error: 'doctor_id e hospital_id são obrigatórios.' });
  }

  try {
    const nextShiftQuery = await pool.query(
      `SELECT shift_date, start_time, end_time, sector 
       FROM shifts 
       WHERE doctor_id = $1 AND hospital_id = $2 AND shift_date >= CURRENT_DATE 
       ORDER BY shift_date ASC, start_time ASC LIMIT 1`,
      [doctor_id, hospital_id]
    );

    const monthHoursQuery = await pool.query(
      `SELECT COUNT(*) * 12 as total_hours 
       FROM shifts 
       WHERE doctor_id = $1 AND hospital_id = $2 
       AND DATE_TRUNC('month', shift_date) = DATE_TRUNC('month', CURRENT_DATE)`,
      [doctor_id, hospital_id]
    );

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
    console.error('Erro na visão geral do médico:', err);
    res.status(500).json({ error: 'Erro ao carregar dados da Visão Geral.' });
  }
});

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
    console.error('Erro ao buscar escala:', err);
    res.status(500).json({ error: 'Erro ao buscar escala de plantões.' });
  }
});

// ==========================================
// ROTAS SAAS: DASHBOARD DO PACIENTE
// ==========================================

app.get('/api/patient/unit-info', async (req, res) => {
  const { hospital_id } = req.query;
  const id = hospital_id || 1;

  try {
    const unitResult = await pool.query(
      `SELECT id, name, 
              COALESCE(address, 'Endereço não informado') as address, 
              COALESCE(phone, '(00) 0000-0000') as phone, 
              COALESCE(opening_hours, '24 Horas') as opening_hours 
       FROM hospitals WHERE id = $1`,
      [id]
    );

    const specsResult = await pool.query(
      `SELECT DISTINCT s.specialty 
       FROM shifts s 
       WHERE s.hospital_id = $1 AND s.specialty IS NOT NULL
       ORDER BY s.specialty ASC`,
      [id]
    );

    res.json({
      unit: unitResult.rows[0] || null,
      specialties: specsResult.rows.map(r => r.specialty)
    });
  } catch (err) {
    console.error('Erro ao buscar dados da unidade:', err);
    res.status(500).json({ error: 'Erro ao carregar dados da unidade.' });
  }
});

app.get('/api/patient/on-duty-team', async (req, res) => {
  const { hospital_id } = req.query;
  const id = hospital_id || 1;

  try {
    const teamResult = await pool.query(
      `SELECT d.name as doctor_name, d.crm, s.sector, s.start_time, s.end_time, s.specialty
       FROM shifts s
       JOIN doctors d ON s.doctor_id = d.id
       WHERE s.hospital_id = $1 
         AND s.shift_date = CURRENT_DATE
       ORDER BY s.start_time ASC`,
      [id]
    );

    res.json(teamResult.rows);
  } catch (err) {
    console.error('Erro ao buscar equipe de plantão:', err);
    res.status(500).json({ error: 'Erro ao carregar equipe de plantão.' });
  }
});

// Inicialização do Servidor
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
