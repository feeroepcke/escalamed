require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const path = require('path');
const { GoogleGenAI } = require('@google/genai');
const { OAuth2Client } = require('google-auth-library');

const app = express();
const PORT = process.env.PORT || 3000;

// Inicialização da IA do Google Gemini e cliente OAuth2 do Google
const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

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

// Helper interno para validar senhas (suporta hash bcrypt e texto puro legado)
async function validarSenha(senhaDigitada, senhaBanco) {
  if (!senhaBanco) return false;
  if (senhaBanco.startsWith('$2a$') || senhaBanco.startsWith('$2b$') || senhaBanco.startsWith('$2y$')) {
    return await bcrypt.compare(senhaDigitada, senhaBanco);
  }
  return senhaDigitada === senhaBanco;
}

// Rota de teste simples
app.get('/api/test', (req, res) => {
  res.json({ status: 'Servidor EscalaMed atualizado e rodando com sucesso!' });
});

// ==========================================
// ROTAS DE AUTENTICAÇÃO GOOGLE OAUTH2 & ONBOARDING
// ==========================================

// 1. Validação do Credential Token enviado pelo Google Sign-In
app.post('/api/auth/google', async (req, res) => {
  const { credential, role } = req.body; // role: 'patient', 'doctor' ou 'manager'

  if (!credential) {
    return res.status(400).json({ error: 'Token do Google não fornecido.' });
  }

  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const { email, name, sub: googleId } = payload;

    let table = 'patients';
    if (role === 'doctor') table = 'doctors';
    if (role === 'manager') table = 'managers';

    // Busca se o usuário já existe no perfil solicitado
    const userQuery = await pool.query(`SELECT * FROM ${table} WHERE email = $1`, [email]);

    if (userQuery.rows.length > 0) {
      const user = userQuery.rows[0];
      return res.json({
        needsOnboarding: false,
        user: {
          id: user.id,
          name: user.name || user.nome,
          email: user.email,
          role: role,
          cpf: user.cpf || null,
          crm: user.crm || null,
          hospital: user.hospital || null
        }
      });
    }

    // Primeiro acesso via Google: necessita do Onboarding para capturar dados adicionais
    return res.json({
      needsOnboarding: true,
      googleUser: { name, email, googleId, role }
    });

  } catch (err) {
    console.error('Erro ao verificar token do Google:', err);
    return res.status(401).json({ error: 'Falha na autenticação com o Google.' });
  }
});

// 2. Finalização do Cadastro após Google OAuth (Onboarding)
app.post('/api/auth/google/onboarding', async (req, res) => {
  const { email, name, role, cpf, crm, hospital, managerRole } = req.body;

  if (!email || !role) {
    return res.status(400).json({ error: 'Dados insuficientes para concluir onboarding.' });
  }

  try {
    let result;

    if (role === 'patient') {
      if (!cpf) return res.status(400).json({ error: 'CPF é obrigatório para pacientes.' });
      result = await pool.query(
        'INSERT INTO patients (name, email, cpf) VALUES ($1, $2, $3) RETURNING id, name, email, cpf',
        [name, email, cpf]
      );
    } else if (role === 'doctor') {
      if (!crm) return res.status(400).json({ error: 'CRM/COREN é obrigatório para profissionais de saúde.' });
      result = await pool.query(
        'INSERT INTO doctors (name, email, crm) VALUES ($1, $2, $3) RETURNING id, name, email, crm',
        [name, email, crm]
      );
      // Vincula à unidade hospitalar padrão (id: 1)
      await pool.query(
        'INSERT INTO doctor_hospitals (doctor_id, hospital_id) VALUES ($1, 1) ON CONFLICT DO NOTHING',
        [result.rows[0].id]
      );
    } else if (role === 'manager') {
      result = await pool.query(
        'INSERT INTO managers (name, email, hospital, role) VALUES ($1, $2, $3, $4) RETURNING id, name, email, hospital, role',
        [name, email, hospital || 'Hospital Geral', managerRole || 'Gestor']
      );
    }

    res.status(201).json({
      message: 'Cadastro concluído com sucesso!',
      user: { ...result.rows[0], role }
    });

  } catch (err) {
    console.error('Erro no onboarding do Google:', err);
    if (err.code === '23505') {
      return res.status(400).json({ error: 'Documento (CPF/CRM) ou e-mail já cadastrado no sistema.' });
    }
    res.status(500).json({ error: 'Erro ao salvar informações do perfil.' });
  }
});

// ==========================================
// ROTAS DE AUTENTICAÇÃO TRADICIONAL
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
    const isMatch = await validarSenha(password, doctor.password_hash || doctor.password);

    if (!isMatch) {
      return res.status(401).json({ error: 'E-mail ou senha incorretos.' });
    }

    res.json({
      message: 'Login bem-sucedido!',
      doctor: { id: doctor.id, name: doctor.name, crm: doctor.crm, email: doctor.email }
    });
  } catch (err) {
    console.error('Erro no login do médico:', err);
    res.status(500).json({ error: 'Erro no servidor ao realizar login.' });
  }
});

// Cadastro de Paciente
app.post('/api/register/patient', async (req, res) => {
  const { name, email, password, cpf } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO patients (name, email, password_hash, cpf) VALUES ($1, $2, $3, $4) RETURNING id, name, email, cpf',
      [name, email, hashedPassword, cpf]
    );

    res.status(201).json({ message: 'Paciente cadastrado com sucesso!', patient: result.rows[0] });
  } catch (err) {
    console.error('Erro no cadastro do paciente:', err);
    if (err.code === '23505') {
      return res.status(400).json({ error: 'E-mail ou CPF já cadastrado.' });
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
    const isMatch = await validarSenha(password, patient.password_hash || patient.password);

    if (!isMatch) {
      return res.status(401).json({ error: 'E-mail ou senha incorretos.' });
    }

    res.json({
      message: 'Login bem-sucedido!',
      patient: { id: patient.id, name: patient.name, email: patient.email, cpf: patient.cpf }
    });
  } catch (err) {
    console.error('Erro no login do paciente:', err);
    res.status(500).json({ error: 'Erro no servidor ao realizar login.' });
  }
});

// Cadastro de Gestor
app.post('/api/register/manager', async (req, res) => {
  const { name, email, password, hospital, role } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO managers (name, email, password_hash, hospital, role) VALUES ($1, $2, $3, $4, $5) RETURNING id, name, email, hospital, role',
      [name, email, hashedPassword, hospital, role]
    );

    res.status(201).json({ message: 'Gestor cadastrado com sucesso!', manager: result.rows[0] });
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
    const isMatch = await validarSenha(password, manager.password_hash || manager.password);

    if (!isMatch) {
      return res.status(401).json({ error: 'E-mail ou senha incorretos.' });
    }

    res.json({
      message: 'Login bem-sucedido!',
      manager: { id: manager.id, name: manager.name, email: manager.email, hospital: manager.hospital, role: manager.role }
    });
  } catch (err) {
    console.error('Erro no login do gestor:', err);
    res.status(500).json({ error: 'Erro no servidor ao realizar login.' });
  }
});

// ==========================================
// ROTAS SAAS: DASHBOARD DO MÉDICO & PACIENTE
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
      `SELECT TO_CHAR(shift_date, 'YYYY-MM-DD') as shift_date, start_time, end_time, sector 
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
      `SELECT s.id, TO_CHAR(s.shift_date, 'YYYY-MM-DD') as shift_date, s.start_time, s.end_time, s.sector, s.doctor_id, d.name as doctor_name
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

// Informações da Unidade para o Paciente
app.get('/api/patient/unit-info', async (req, res) => {
  const { hospital_id } = req.query;
  const id = hospital_id || 1;

  try {
    const unitResult = await pool.query(
      `SELECT id, name, 
              COALESCE(address, 'Endereço não informado') as address, 
              COALESCE(phone, '(00) 0000-0000') as phone, 
              COALESCE(opening_hours, '24 Horas') as opening_hours,
              COALESCE(wait_time, '~25 min') as wait_time,
              COALESCE(demand, 'Média') as demand
       FROM hospitals WHERE id = $1`,
      [id]
    );

    const specsResult = await pool.query(
      `SELECT DISTINCT specialty 
       FROM shifts 
       WHERE hospital_id = $1 AND specialty IS NOT NULL AND specialty != ''
       ORDER BY specialty ASC`,
      [id]
    );

    const specialtiesList = specsResult.rows.map(r => ({
      name: r.specialty,
      doctors: 'Corpo clínico atuante na unidade'
    }));

    res.json({
      unit: unitResult.rows[0] || {
        id,
        name: 'Unidade Hospitalar',
        address: 'Endereço registrado na rede principal',
        phone: '(47) 3300-0000',
        opening_hours: '24 Horas',
        wait_time: '~25 min',
        demand: 'Média'
      },
      specialties: specialtiesList
    });
  } catch (err) {
    console.error('Erro ao buscar dados da unidade:', err);
    res.status(500).json({ error: 'Erro ao carregar dados da unidade.' });
  }
});

// Equipe em plantão hoje (Anonimizada para o paciente)
app.get('/api/patient/on-duty-team', async (req, res) => {
  const { hospital_id } = req.query;
  const id = hospital_id || 1;

  try {
    const teamResult = await pool.query(
      `SELECT 
         COALESCE(s.specialty, 'Atendimento Geral') as category,
         s.sector,
         COUNT(s.doctor_id)::int as count
       FROM shifts s
       WHERE s.hospital_id = $1 
         AND s.shift_date = CURRENT_DATE
         AND s.doctor_id IS NOT NULL
       GROUP BY s.specialty, s.sector`,
      [id]
    );

    res.json(teamResult.rows);
  } catch (err) {
    console.error('Erro ao buscar equipe de plantão:', err);
    res.status(500).json({ error: 'Erro ao carregar equipe de plantão.' });
  }
});

// Cronograma para o Gráfico de Gantt do Paciente
app.get('/api/patient/gantt-schedule', async (req, res) => {
  const { hospital_id } = req.query;
  const id = hospital_id || 1;

  try {
    const result = await pool.query(
      `SELECT 
         id,
         COALESCE(specialty, 'Clínica Geral') as specialty,
         sector,
         TO_CHAR(start_time, 'HH24:MI') as start_time,
         TO_CHAR(end_time, 'HH24:MI') as end_time,
         EXTRACT(HOUR FROM start_time) as start_hour,
         EXTRACT(HOUR FROM end_time) as end_hour
       FROM shifts
       WHERE hospital_id = $1 
         AND shift_date = CURRENT_DATE
         AND doctor_id IS NOT NULL
       ORDER BY start_time ASC`,
      [id]
    );

    const ganttData = result.rows.map(row => {
      const startH = parseFloat(row.start_hour) || 7;
      let endH = parseFloat(row.end_hour) || 19;
      
      if (endH <= startH) endH += 24;

      const startRel = (startH >= 7 ? startH - 7 : startH + 17);
      const duration = endH - startH;

      const startPercent = Math.min(100, Math.max(0, (startRel / 24) * 100));
      const widthPercent = Math.min(100 - startPercent, Math.max(5, (duration / 24) * 100));

      return {
        id: row.id,
        specialty: row.specialty,
        sector: row.sector,
        start_time: row.start_time,
        end_time: row.end_time,
        start_percent: Math.round(startPercent),
        width_percent: Math.round(widthPercent)
      };
    });

    res.json(ganttData);
  } catch (err) {
    console.error('Erro ao buscar cronograma de Gantt do paciente:', err);
    res.status(500).json({ error: 'Erro ao carregar cronograma visual.' });
  }
});

// Salvar/Atualizar Preferências do Médico
app.post('/api/doctor/preferences', async (req, res) => {
  const { doctor_id, horas_por_turno, max_plantoes_semana, turno_preferido, dias_indisponiveis } = req.body;

  if (!doctor_id) {
    return res.status(400).json({ error: 'doctor_id é obrigatório.' });
  }

  try {
    const result = await pool.query(
      `INSERT INTO doctor_preferences (doctor_id, horas_por_turno, max_plantoes_semana, turno_preferido, dias_indisponiveis)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (doctor_id) DO UPDATE SET
         horas_por_turno = EXCLUDED.horas_por_turno,
         max_plantoes_semana = EXCLUDED.max_plantoes_semana,
         turno_preferido = EXCLUDED.turno_preferido,
         dias_indisponiveis = EXCLUDED.dias_indisponiveis
       RETURNING *`,
      [doctor_id, horas_por_turno || 12, max_plantoes_semana || 3, turno_preferido || 'qualquer', dias_indisponiveis || '']
    );

    res.json({ message: 'Preferências salvas com sucesso!', preferences: result.rows[0] });
  } catch (err) {
    console.error('Erro ao salvar preferências do médico:', err);
    res.status(500).json({ error: 'Erro ao salvar preferências.' });
  }
});

// Médico assume um plantão vago diretamente
app.post('/api/doctor/shifts/:id/claim', async (req, res) => {
  const { id } = req.params;
  const { doctor_id } = req.body;

  if (!doctor_id) {
    return res.status(400).json({ error: 'doctor_id é obrigatório.' });
  }

  try {
    const result = await pool.query(
      'UPDATE shifts SET doctor_id = $1 WHERE id = $2 AND doctor_id IS NULL RETURNING *',
      [doctor_id, id]
    );

    if (result.rowCount === 0) {
      return res.status(409).json({ error: 'Plantão não encontrado ou já preenchido por outro médico.' });
    }

    res.json({ message: 'Plantão assumido com sucesso!', shift: result.rows[0] });
  } catch (err) {
    console.error('Erro ao assumir plantão:', err);
    res.status(500).json({ error: 'Erro ao assumir plantão.' });
  }
});

// ==========================================
// ROTAS ADM: APRECIAÇÃO DE SOLICITAÇÕES
// ==========================================

// Lista todas as solicitações pendentes (trocas e candidaturas)
app.get('/api/manager/requests', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT sr.id, sr.request_type, sr.status, sr.created_at,
              TO_CHAR(s.shift_date, 'YYYY-MM-DD') as shift_date, s.start_time, s.end_time, s.sector, s.id as shift_id,
              d1.name as requester_name, d1.crm as requester_crm,
              d2.name as target_name
       FROM shift_requests sr
       JOIN shifts s ON sr.shift_id = s.id
       JOIN doctors d1 ON sr.requester_doctor_id = d1.id
       LEFT JOIN doctors d2 ON sr.target_doctor_id = d2.id
       WHERE sr.status = 'pendente_adm'
       ORDER BY sr.created_at DESC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar solicitações:', err);
    res.status(500).json({ error: 'Erro ao carregar solicitações pendentes.' });
  }
});

// ADM aprova ou rejeita solicitação (Troca ou Candidatura)
app.patch('/api/manager/requests/:id/respond', async (req, res) => {
  const { id } = req.params;
  const { action } = req.body;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const reqResult = await client.query('SELECT * FROM shift_requests WHERE id = $1', [id]);
    if (reqResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Solicitação não encontrada.' });
    }

    const requestData = reqResult.rows[0];

    if (action === 'aprovar') {
      const newDoctorId = requestData.target_doctor_id || requestData.requester_doctor_id;
      await client.query('UPDATE shifts SET doctor_id = $1 WHERE id = $2', [newDoctorId, requestData.shift_id]);
      await client.query("UPDATE shift_requests SET status = 'aprovado' WHERE id = $1", [id]);
    } else {
      await client.query("UPDATE shift_requests SET status = 'rejeitado' WHERE id = $1", [id]);
    }

    await client.query('COMMIT');
    res.json({ message: `Solicitação ${action === 'aprovar' ? 'aprovada' : 'rejeitada'} com sucesso!` });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Erro ao responder solicitação:', err);
    res.status(500).json({ error: 'Erro ao processar resposta.' });
  } finally {
    client.release();
  }
});

// ==========================================
// ROTAS ADM: PREFERÊNCIAS DOS MÉDICOS
// ==========================================

app.get('/api/manager/doctors-preferences', async (req, res) => {
  const { hospital_id } = req.query;
  try {
    const result = await pool.query(
      `SELECT d.id, d.name, d.crm, d.email,
              COALESCE(dp.horas_por_turno, 12) as horas_por_turno,
              COALESCE(dp.max_plantoes_semana, 3) as max_plantoes_semana,
              COALESCE(dp.turno_preferido, 'qualquer') as turno_preferido,
              COALESCE(dp.dias_indisponiveis, 'Nenhum') as dias_indisponiveis
       FROM doctors d
       JOIN doctor_hospitals dh ON d.id = dh.doctor_id
       LEFT JOIN doctor_preferences dp ON d.id = dp.doctor_id
       WHERE dh.hospital_id = $1
       ORDER BY d.name ASC`,
      [hospital_id || 1]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar preferências dos médicos:', err);
    res.status(500).json({ error: 'Erro ao buscar dados dos médicos.' });
  }
});

// ==========================================
// ROTAS ADM: FALTAS, ATESTADOS E REGRAS DE 48H
// ==========================================

app.get('/api/manager/absences/weekly', async (req, res) => {
  const { start_date, end_date } = req.query;

  if (!start_date || !end_date) {
    return res.status(400).json({ error: 'start_date e end_date são obrigatórios.' });
  }

  try {
    const result = await pool.query(
      `SELECT da.id, TO_CHAR(da.absence_date, 'YYYY-MM-DD') as absence_date, da.reason, da.document_url, da.status, da.created_at,
              d.name as doctor_name, d.crm,
              s.sector, s.start_time, s.end_time,
              CASE 
                WHEN da.status = 'pendente' AND da.created_at < NOW() - INTERVAL '48 hours' THEN true 
                ELSE false 
              END as prazo_48h_estourado
       FROM doctor_absences da
       JOIN doctors d ON da.doctor_id = d.id
       LEFT JOIN shifts s ON da.shift_id = s.id
       WHERE da.absence_date BETWEEN $1 AND $2
       ORDER BY da.absence_date ASC`,
      [start_date, end_date]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar faltas semanais:', err);
    res.status(500).json({ error: 'Erro ao carregar calendário de faltas.' });
  }
});

// Inicialização do Servidor
app.listen(PORT, () => {
  console.log(`Servidor EscalaMed rodando com sucesso na porta ${PORT}`);
});