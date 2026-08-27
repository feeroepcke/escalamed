const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware para ler JSON
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Configuração do Banco de Dados SQLite
const dbFile = path.join(__dirname, 'escalamed.db');
const db = new sqlite3.Database(dbFile, (err) => {
    if (err) {
        console.error('Erro ao abrir o banco de dados', err.message);
    } else {
        console.log('Conectado ao banco de dados SQLite.');
        initDatabase();
    }
});

function initDatabase() {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cpf TEXT UNIQUE,
        email TEXT,
        password TEXT,
        category TEXT,
        council TEXT,
        registry TEXT,
        user_type TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS shifts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        doctor_name TEXT,
        sector TEXT,
        date TEXT,
        time TEXT,
        status TEXT
    )`);
}

// Rota de Cadastro de Médico
api_url = '/api/register-doctor';
app.post('/api/register-doctor', (req, res) => {
    const { cpf, email, password, category, council, registry } = req.body;
    const query = `INSERT INTO users (cpf, email, password, category, council, registry, user_type) VALUES (?, ?, ?, ?, ?, ?, 'doctor')`;
    
    db.run(query, [cpf, email, password, category, council, registry], function(err) {
        if (err) {
            return res.status(400).json({ error: 'Erro ao cadastrar. CPF ou registro já podem existir.' });
        }
        res.json({ success: true, userId: this.lastID });
    });
});

// Iniciar Servidor
app.listen(PORT, () => {
    console.log(`Servidor rodando em http://localhost:${PORT}`);
});