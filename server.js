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
}

// Rota de Cadastro de Médico
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

// Rota de Login do Médico
app.post('/api/login-doctor', (req, res) => {
    const { email, password } = req.body;
    const query = `SELECT * FROM users WHERE email = ? AND password = ? AND user_type = 'doctor'`;
    
    db.get(query, [email, password], (err, row) => {
        if (err) {
            return res.status(500).json({ error: 'Erro no servidor.' });
        }
        if (!row) {
            return res.status(401).json({ error: 'E-mail ou senha incorretos.' });
        }
        res.json({ 
            success: true, 
            user: { 
                registry: row.registry, 
                email: row.email, 
                category: row.category, 
                council: row.council 
            } 
        });
    });
});

// Iniciar Servidor
app.listen(PORT, () => {
    console.log(`Servidor rodando em http://localhost:${PORT}`);
});