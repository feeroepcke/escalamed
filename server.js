const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Conectar ao Banco de Dados SQLite
const db = new sqlite3.Database('./escalamed.db', (err) => {
    if (err) console.error('Erro ao abrir o banco de dados', err.message);
    else console.log('Conectado ao banco de dados SQLite.');
});

// Criar tabelas se não existirem
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS doctors (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        category TEXT,
        council TEXT,
        registry TEXT,
        cpf TEXT,
        email TEXT UNIQUE,
        password TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS patients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cpf TEXT UNIQUE,
        email TEXT,
        password TEXT
    )`);
});

// Rota de Cadastro de Médico
app.post('/api/register-doctor', (req, res) => {
    const { category, council, registry, cpf, email, password } = req.body;
    const query = `INSERT INTO doctors (category, council, registry, cpf, email, password) VALUES (?, ?, ?, ?, ?, ?)`;
    
    db.run(query, [category, council, registry, cpf, email, password], function(err) {
        if (err) {
            return res.status(400).json({ error: 'E-mail já cadastrado ou dados inválidos.' });
        }
        res.status(201).json({ message: 'Médico cadastrado com sucesso!', id: this.lastID });
    });
});

// Rota de Login de Médico
app.post('/api/login-doctor', (req, res) => {
    const { email, password } = req.body;
    db.get(`SELECT * FROM doctors WHERE email = ? AND password = ?`, [email, password], (err, row) => {
        if (err) return res.status(500).json({ error: 'Erro no servidor.' });
        if (!row) return res.status(401).json({ error: 'E-mail ou senha incorretos.' });
        res.json({ message: 'Login bem-sucedido', user: row });
    });
});

// Rota de Cadastro de Paciente
app.post('/api/register-patient', (req, res) => {
    const { cpf, email, password } = req.body;
    const query = `INSERT INTO patients (cpf, email, password) VALUES (?, ?, ?)`;
    
    db.run(query, [cpf, email, password], function(err) {
        if (err) {
            return res.status(400).json({ error: 'CPF já cadastrado.' });
        }
        res.status(201).json({ message: 'Paciente cadastrado com sucesso!', id: this.lastID });
    });
});

// Rota de Login de Paciente
app.post('/api/login-patient', (req, res) => {
    const { loginId, password } = req.body;
    db.get(`SELECT * FROM patients WHERE (email = ? OR cpf = ?) AND password = ?`, [loginId, loginId, password], (err, row) => {
        if (err) return res.status(500).json({ error: 'Erro no servidor.' });
        if (!row) return res.status(401).json({ error: 'Credenciais inválidas.' });
        res.json({ message: 'Login bem-sucedido', user: row });
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});