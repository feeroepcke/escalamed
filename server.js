require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const path = require('path');
const { GoogleGenAI } = require('@google/genai');

const app = express();
const PORT = process.env.PORT || 3000;

// Inicialização da IA do Google Gemini
const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });

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

// Helper interno para validar senhas (suporta senhas hash com bcrypt ou texto simples legado)
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

// Cadastro de Gestor
app.post('/api/register/manager', async (req, res) => {
  const { name, hospital, role, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    let result;

    try {
      result = await pool.query(
        'INSERT INTO managers (name, hospital, role, email, password) VALUES ($1, $2, $3, $4, $5) RETURNING id, name, hospital, role, email',
        [name, hospital, role, email, hashedPassword]
      );
    } catch (dbErr1) {
      if (dbErr1.code === '42703') { // Coluna 'password' não existe
        try {
          result = await pool.query(
            'INSERT INTO managers (name, hospital, role, email, password_hash) VALUES ($1, $2, $3, $4, $5) RETURNING id, name, hospital, role, email',
            [name, hospital, role, email, hashedPassword]
          );
        } catch (dbErr2) {
          if (dbErr2.code === '42703') { // Schema em português
            result = await pool.query(
              'INSERT INTO managers (nome, hospital, cargo, email, senha) VALUES ($1, $2, $3, $4, $5) RETURNING id, nome as name, hospital, cargo as role, email',
              [name, hospital, role, email, hashedPassword]
            );
          } else {
            throw dbErr2;
          }
        }
      } else {
        throw dbErr1;
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

app.get('/api/manager/shifts', async (req, res) => {
  const { hospital_id } = req.query;

  if (!hospital_id) {
    return res.status(400).json({ error: 'hospital_id é obrigatório.' });
  }

  try {
    const result = await pool.query(
      `SELECT s.id, TO_CHAR(s.shift_date, 'YYYY-MM-DD') as shift_date, s.start_time, s.end_time, s.sector, s.specialty, s.doctor_id, d.name as doctor_name
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
// ROTAS DE IA: GERADOR INTELIGENTE DE ESCALAS
// ==========================================

app.post('/api/manager/ai-generate-schedule', async (req, res) => {
  const { hospital_id } = req.body;

  if (!hospital_id) {
    return res.status(400).json({ error: 'hospital_id é obrigatório.' });
  }

  try {
    // 1. Buscar plantões sem médico atribuído (vagos), formatando a data em YYYY-MM-DD
    const openShiftsResult = await pool.query(
      `SELECT id, TO_CHAR(shift_date, 'YYYY-MM-DD') as shift_date, start_time, end_time, sector, specialty 
       FROM shifts 
       WHERE hospital_id = $1 AND doctor_id IS NULL AND shift_date >= CURRENT_DATE
       ORDER BY shift_date ASC, start_time ASC`,
      [hospital_id]
    );

    const openShifts = openShiftsResult.rows;

    if (openShifts.length === 0) {
      return res.status(200).json({ 
        message: 'Não há plantões vagos pendentes de alocação para esta unidade.',
        allocations: [] 
      });
    }

    // 2. Buscar médicos e suas preferências
    const doctorsResult = await pool.query(
      `SELECT d.id, d.name, d.crm, 
              COALESCE(dp.horas_por_turno, 12) as horas_por_turno,
              COALESCE(dp.max_plantoes_semana, 3) as max_plantoes_semana,
              COALESCE(dp.turno_preferido, 'qualquer') as turno_preferido,
              COALESCE(dp.dias_indisponiveis, '') as dias_indisponiveis
       FROM doctors d
       JOIN doctor_hospitals dh ON d.id = dh.doctor_id
       LEFT JOIN doctor_preferences dp ON d.id = dp.doctor_id
       WHERE dh.hospital_id = $1`,
      [hospital_id]
    );

    const doctors = doctorsResult.rows;

    if (doctors.length === 0) {
      return res.status(400).json({ error: 'Nenhum médico vinculado a esta unidade hospitalar.' });
    }

    // 3. Montar o prompt estruturado
    const prompt = `
Você é o assistente gestor de escalas médicas do sistema EscalaMed.
Sua missão é distribuir os plantões vagos abaixo entre os médicos disponíveis, respeitando as preferências de cada um da melhor forma possível.

[PLANTÕES VAGOS]:
${JSON.stringify(openShifts, null, 2)}

[MÉDICOS DISPONÍVEIS E SUAS PREFERÊNCIAS]:
${JSON.stringify(doctors, null, 2)}

REGRAS DE ALOCAÇÃO:
1. Tente distribuir os plantões de forma justa sem ultrapassar o 'max_plantoes_semana' de cada médico.
2. Evite escalar o médico em seus 'dias_indisponiveis' (se houver algum dia especificado).
3. Respeite o 'turno_preferido' quando viável ('manha', 'tarde', 'noite' ou 'qualquer').
4. Retorne EXCLUSIVAMENTE um array JSON contendo objetos no seguinte formato, sem texto adicional ou explicações fora do JSON:

[
  {
    "shift_id": 12,
    "doctor_id": 5,
    "doctor_name": "Dr. Nome",
    "reasoning": "Alocado por compatibilidade com horário da manhã e limite semanal disponível."
  }
]
`;

    // 4. Chamada para a IA Gemini
    const response = await ai.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: prompt,
      config: {
        responseMimeType: 'application/json',
      }
    });

    const aiTextResponse = response.text;
    
    // Tratamento defensivo para parsing do JSON retornado pela IA
    let allocations = [];
    try {
      allocations = JSON.parse(aiTextResponse);
    } catch (parseErr) {
      console.error('Erro ao parsear resposta JSON da IA:', aiTextResponse);
      return res.status(500).json({ error: 'A IA retornou uma resposta em formato inválido. Tente novamente.' });
    }

    res.json({
      message: 'Sugestão de escala gerada com sucesso pela IA!',
      total_vagas: openShifts.length,
      allocations
    });

  } catch (err) {
    console.error('Erro ao gerar escala automática via IA:', err);
    res.status(500).json({ error: 'Erro ao processar a escala inteligente com IA.' });
  }
});

// Aplicar alocações da IA em lote
app.post('/api/manager/apply-ai-schedule', async (req, res) => {
  const { allocations } = req.body;

  if (!Array.isArray(allocations) || allocations.length === 0) {
    return res.status(400).json({ error: 'Nenhuma alocação válida fornecida.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    for (const item of allocations) {
      if (item.shift_id && item.doctor_id) {
        await client.query(
          `UPDATE shifts SET doctor_id = $1 WHERE id = $2`,
          [item.doctor_id, item.shift_id]
        );
      }
    }

    await client.query('COMMIT');
    res.json({ message: 'Escala atualizada com sucesso com base nas sugestões da IA!' });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Erro ao aplicar escala da IA:', err);
    res.status(500).json({ error: 'Erro ao salvar alocações da IA no banco de dados.' });
  } finally {
    client.release();
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

    // Converte os horários em percentuais para o posicionamento da barra de Gantt
    const ganttData = result.rows.map(row => {
      const startH = parseFloat(row.start_hour) || 7;
      let endH = parseFloat(row.end_hour) || 19;
      
      // Ajuste para turnos que viram a noite
      if (endH <= startH) endH += 24;

      // Considerando janela total de 24h a partir das 07:00
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
    const checkShift = await pool.query('SELECT * FROM shifts WHERE id = $1', [id]);
    if (checkShift.rows.length === 0) {
      return res.status(404).json({ error: 'Plantão não encontrado.' });
    }

    if (checkShift.rows[0].doctor_id !== null) {
      return res.status(400).json({ error: 'Este plantão já possui médico atribuído.' });
    }

    const result = await pool.query(
      'UPDATE shifts SET doctor_id = $1 WHERE id = $2 RETURNING *',
      [doctor_id, id]
    );

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
  const { action } = req.body; // 'aprovar' ou 'rejeitar'

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
      
      // Atribui o novo médico ao plantão
      await client.query('UPDATE shifts SET doctor_id = $1 WHERE id = $2', [newDoctorId, requestData.shift_id]);
      // Atualiza status da solicitação
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

// Lista médicos e suas preferências cadastradas
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

// Visão semanal de faltas para o calendário e notificações de 48h
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