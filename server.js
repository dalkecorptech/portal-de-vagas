require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
// Configuração de segurança CORS
const corsOptions = {
    origin: [
        'https://nome-do-seu-projeto.vercel.app', // Substitua pela URL real gerada pela Vercel
        'http://localhost:5500', // Para você testar no seu computador
        'http://localhost:3000'
    ],
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
    optionsSuccessStatus: 204
};

app.use(cors(corsOptions));

app.use(express.json());

// Configuração de Conexão com o PostgreSQL (Neon.tech)
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false } // Necessário para o Neon.tech e Render
});

const JWT_SECRET = process.env.JWT_SECRET || 'chave_secreta_super_segura_aqui';

// ==========================================
// MIDDLEWARE DE AUTENTICAÇÃO E AUTORIZAÇÃO
// ==========================================
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Acesso negado. Token não fornecido.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token inválido ou expirado.' });
        req.user = user;
        next();
    });
};

const requireRole = (role) => {
    return (req, res, next) => {
        if (req.user.tipo_usuario !== role) {
            return res.status(403).json({ error: `Acesso restrito para ${role}s.` });
        }
        next();
    };
};

// ==========================================
// ROTAS DE AUTENTICAÇÃO (RNF-04)
// ==========================================

// 1. Cadastro de Usuário (Exemplo focado na Empresa para permitir postagem)
app.post('/api/auth/register', async (req, res) => {
    const { email, senha, tipo_usuario, nome_fantasia, cnpj } = req.body;
    
    if (!['admin', 'candidato', 'empresa'].includes(tipo_usuario)) {
        return res.status(400).json({ error: 'Tipo de usuário inválido.' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN'); // Inicia a transação

        // Criptografa a senha
        const salt = await bcrypt.genSalt(10);
        const senhaHash = await bcrypt.hash(senha, salt);

        // Insere na tabela 'usuarios'
        const userResult = await client.query(
            'INSERT INTO usuarios (email, senha, tipo_usuario) VALUES ($1, $2, $3) RETURNING id, email, tipo_usuario',
            [email, senhaHash, tipo_usuario]
        );
        const novoUsuario = userResult.rows[0];

        // Se for empresa, cria o perfil correspondente
        if (tipo_usuario === 'empresa') {
            await client.query(
                'INSERT INTO empresas (usuario_id, nome_fantasia, cnpj) VALUES ($1, $2, $3)',
                [novoUsuario.id, nome_fantasia, cnpj]
            );
        }
        // Nota: Para 'candidatos', você adicionaria a lógica correspondente aqui.

        await client.query('COMMIT');
        res.status(201).json({ message: 'Usuário cadastrado com sucesso!', usuario: novoUsuario });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Erro no cadastro:', error);
        res.status(500).json({ error: 'Erro ao registrar usuário. Verifique se o email ou documento já existe.' });
    } finally {
        client.release();
    }
});

// 2. Login e Geração de JWT
app.post('/api/auth/login', async (req, res) => {
    const { email, senha } = req.body;

    try {
        const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Email ou senha incorretos.' });
        }

        const usuario = result.rows[0];
        const senhaValida = await bcrypt.compare(senha, usuario.senha);

        if (!senhaValida) {
            return res.status(401).json({ error: 'Email ou senha incorretos.' });
        }

        // Gera o Token JWT
        const token = jwt.sign(
            { id: usuario.id, email: usuario.email, tipo_usuario: usuario.tipo_usuario },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({ message: 'Login bem-sucedido', token, tipo_usuario: usuario.tipo_usuario });
    } catch (error) {
        console.error('Erro no login:', error);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

// ==========================================
// ROTAS DE VAGAS
// ==========================================

// 3. Rota Protegida: Publicar Nova Vaga (Apenas Empresas)
app.post('/api/vagas', authenticateToken, requireRole('empresa'), async (req, res) => {
    const { titulo, descricao, requisitos, salario_min, salario_max, cidade, estado } = req.body;
    const usuarioId = req.user.id;

    try {
        // Busca o ID da empresa vinculada a este usuário logado
        const empresaResult = await pool.query('SELECT id FROM empresas WHERE usuario_id = $1', [usuarioId]);
        
        if (empresaResult.rows.length === 0) {
            return res.status(404).json({ error: 'Perfil de empresa não encontrado.' });
        }
        
        const empresaId = empresaResult.rows[0].id;

        // Insere a vaga
        const insertVaga = await pool.query(
            `INSERT INTO vagas 
            (empresa_id, titulo, descricao, requisitos, salario_min, salario_max, cidade, estado, tipo_vaga) 
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'direta') RETURNING *`,
            [empresaId, titulo, descricao, requisitos, salario_min, salario_max, cidade, estado]
        );

        res.status(201).json({ message: 'Vaga publicada com sucesso!', vaga: insertVaga.rows[0] });
    } catch (error) {
        console.error('Erro ao publicar vaga:', error);
        res.status(500).json({ error: 'Erro ao cadastrar a vaga.' });
    }
});

// 4. Rota Pública: Listar Vagas com Filtros Básicos
app.get('/api/vagas', async (req, res) => {
    const { busca, cidade } = req.query;
    
    // Constrói a query dinamicamente
    let query = `
        SELECT v.*, e.nome_fantasia as nome_empresa 
        FROM vagas v
        LEFT JOIN empresas e ON v.empresa_id = e.id
        WHERE v.status = 'ativo'
    `;
    const params = [];
    let paramIndex = 1;

    if (busca) {
        query += ` AND v.titulo ILIKE $${paramIndex}`;
        params.push(`%${busca}%`);
        paramIndex++;
    }

    if (cidade) {
        query += ` AND v.cidade ILIKE $${paramIndex}`;
        params.push(`%${cidade}%`);
        paramIndex++;
    }

    query += ' ORDER BY v.data_publicacao DESC';

    try {
        const result = await pool.query(query, params);
        res.json(result.rows);
    } catch (error) {
        console.error('Erro ao buscar vagas:', error);
        res.status(500).json({ error: 'Erro interno ao consultar vagas.' });
    }
});

// ==========================================
// INICIALIZAÇÃO DO SERVIDOR
// ==========================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
                                     
