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
        'https://portal-de-vagas-frontend.vercel.app', // Substitua pela URL real gerada pela Vercel
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

// 1. Rota POST /api/auth/cadastro
app.post('/api/auth/cadastro', async (req, res) => {
    const { email, senha, tipo_usuario, nome, documento } = req.body;

    // Validação básica do tipo de usuário
    if (!['candidato', 'empresa'].includes(tipo_usuario)) {
        return res.status(400).json({ error: 'Tipo de usuário inválido.' });
    }

    // Solicita um client isolado do pool para gerenciar a transação SQL
    const client = await pool.connect();

    try {
        await client.query('BEGIN'); // Inicia a transação SQL

        // 1. Verifica se o e-mail já está cadastrado na tabela usuarios
        const emailCheck = await client.query('SELECT id FROM usuarios WHERE email = $1', [email]);
        if (emailCheck.rows.length > 0) {
            throw new Error('Este e-mail já está em uso.');
        }

        // 2. Verifica se o documento (CPF ou CNPJ) já existe na respectiva tabela
        if (tipo_usuario === 'candidato') {
            const cpfCheck = await client.query('SELECT id FROM candidatos WHERE cpf = $1', [documento]);
            if (cpfCheck.rows.length > 0) throw new Error('Este CPF já está cadastrado.');
        } else if (tipo_usuario === 'empresa') {
            const cnpjCheck = await client.query('SELECT id FROM empresas WHERE cnpj = $1', [documento]);
            if (cnpjCheck.rows.length > 0) throw new Error('Este CNPJ já está cadastrado.');
        }

        // 3. Criptografa a senha com bcrypt
        const salt = await bcrypt.genSalt(10);
        const senhaHash = await bcrypt.hash(senha, salt);

        // 4. Salva na tabela base 'usuarios' e recupera o ID gerado
        const insertUsuario = await client.query(
            'INSERT INTO usuarios (email, senha, tipo_usuario) VALUES ($1, $2, $3) RETURNING id, email, tipo_usuario',
            [email, senhaHash, tipo_usuario]
        );
        const novoUsuario = insertUsuario.rows[0];

        // 5. Salva na tabela específica (Candidato ou Empresa) usando o ID do usuário criado
        if (tipo_usuario === 'candidato') {
            await client.query(
                'INSERT INTO candidatos (usuario_id, nome, cpf) VALUES ($1, $2, $3)',
                [novoUsuario.id, nome, documento]
            );
        } else if (tipo_usuario === 'empresa') {
            await client.query(
                'INSERT INTO empresas (usuario_id, nome_fantasia, cnpj) VALUES ($1, $2, $3)',
                [novoUsuario.id, nome, documento]
            );
        }

        await client.query('COMMIT'); // Confirma a transação
        
        res.status(201).json({ 
            message: 'Cadastro realizado com sucesso!', 
            usuario: novoUsuario 
        });

    } catch (error) {
        await client.query('ROLLBACK'); // Desfaz tudo em caso de erro para manter a integridade
        console.error('Erro no cadastro:', error);
        
        // Retorna o erro específico que disparamos ou um erro genérico
        const errorMessage = error.message.includes('já') ? error.message : 'Erro interno ao realizar o cadastro.';
        res.status(400).json({ error: errorMessage });
    } finally {
        client.release(); // Libera o client de volta para o pool
    }
});


// 2. Rota POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
    const { email, senha } = req.body;

    try {
        // 1. Busca o usuário pelo e-mail
        const userResult = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
        
        if (userResult.rows.length === 0) {
            return res.status(401).json({ error: 'Credenciais inválidas.' }); // Evita expor que o email não existe
        }

        const usuario = userResult.rows[0];

        // 2. Compara a senha digitada com a senha criptografada do banco
        const senhaValida = await bcrypt.compare(senha, usuario.senha);

        if (!senhaValida) {
            return res.status(401).json({ error: 'Credenciais inválidas.' });
        }

        // 3. Gera o Token JWT contendo apenas as informações essenciais
        const token = jwt.sign(
            { 
                id: usuario.id, 
                tipo_usuario: usuario.tipo_usuario 
            },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        // 4. Retorna os dados com sucesso
        res.json({
            message: 'Login bem-sucedido!',
            token: token,
            usuario: {
                id: usuario.id,
                email: usuario.email,
                tipo_usuario: usuario.tipo_usuario
            }
        });

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
                                              
