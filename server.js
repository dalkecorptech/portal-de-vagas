require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();

const corsOptions = {
    origin: [
        'https://portal-de-vagas-frontend.vercel.app',
        'http://localhost:5500',
        'http://localhost:3000'
    ],
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
    optionsSuccessStatus: 204
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' })); // Limite ampliado para suportar a conversão Base64 de PDFs/DOCs

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = process.env.JWT_SECRET || 'chave_secreta_super_segura_aqui';

// ==========================================
// MIDDLEWARES E FUNÇÕES UTILITÁRIAS
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

const parseBase64 = (dataUri) => {
    const matches = dataUri.match(/^data:(.+);base64,(.+)$/);
    if (!matches || matches.length !== 3) return null;
    return { mimeType: matches[1], data: matches[2] };
};

// ==========================================
// ROTAS DE AUTENTICAÇÃO
// ==========================================
app.post('/api/auth/cadastro', async (req, res) => {
    const { email, senha, tipo_usuario, nome, documento } = req.body;
    if (!email || !senha || !tipo_usuario || !nome || !documento) {
        return res.status(400).json({ error: 'Todos os campos são obrigatórios para o cadastro.' });
    }
    if (!['candidato', 'empresa'].includes(tipo_usuario)) {
        return res.status(400).json({ error: 'Tipo de usuário inválido.' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const emailCheck = await client.query('SELECT id FROM usuarios WHERE email = $1', [email]);
        if (emailCheck.rows.length > 0) throw new Error('Este e-mail já está em uso.');

        if (tipo_usuario === 'candidato') {
            const cpfCheck = await client.query('SELECT id FROM candidatos WHERE cpf = $1', [documento]);
            if (cpfCheck.rows.length > 0) throw new Error('Este CPF já está cadastrado.');
        } else if (tipo_usuario === 'empresa') {
            const cnpjCheck = await client.query('SELECT id FROM empresas WHERE cnpj = $1', [documento]);
            if (cnpjCheck.rows.length > 0) throw new Error('Este CNPJ já está cadastrado.');
        }

        const salt = await bcrypt.genSalt(10);
        const senhaHash = await bcrypt.hash(senha, salt);

        const insertUsuario = await client.query(
            'INSERT INTO usuarios (email, senha, tipo_usuario) VALUES ($1, $2, $3) RETURNING id, email, tipo_usuario',
            [email, senhaHash, tipo_usuario]
        );
        const novoUsuario = insertUsuario.rows[0];

        if (tipo_usuario === 'candidato') {
            await client.query('INSERT INTO candidatos (usuario_id, nome, cpf) VALUES ($1, $2, $3)', [novoUsuario.id, nome, documento]);
        } else if (tipo_usuario === 'empresa') {
            await client.query('INSERT INTO empresas (usuario_id, nome_fantasia, cnpj) VALUES ($1, $2, $3)', [novoUsuario.id, nome, documento]);
        }

        await client.query('COMMIT');
        res.status(201).json({ message: 'Cadastro realizado com sucesso!', usuario: novoUsuario });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Erro no cadastro:', error);
        res.status(400).json({ error: error.message.includes('já') ? error.message : 'Erro interno ao realizar o cadastro.' });
    } finally {
        client.release();
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, senha } = req.body;
    if (!email || !senha) return res.status(400).json({ error: 'E-mail e senha são obrigatórios.' });

    try {
        const userResult = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
        if (userResult.rows.length === 0) return res.status(401).json({ error: 'Credenciais inválidas.' });

        const usuario = userResult.rows[0];
        const senhaValida = await bcrypt.compare(senha, usuario.senha);
        if (!senhaValida) return res.status(401).json({ error: 'Credenciais inválidas.' });

        const token = jwt.sign({ id: usuario.id, tipo_usuario: usuario.tipo_usuario }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ message: 'Login bem-sucedido!', token: token, usuario: { id: usuario.id, email: usuario.email, tipo_usuario: usuario.tipo_usuario } });
    } catch (error) {
        console.error('Erro no login:', error);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

// ==========================================
// ROTAS DE CURRÍCULO E ANEXOS
// ==========================================
app.get('/api/curriculo', authenticateToken, requireRole('candidato'), async (req, res) => {
    try {
        const candidatoResult = await pool.query('SELECT id FROM candidatos WHERE usuario_id = $1', [req.user.id]);
        if (candidatoResult.rows.length === 0) return res.status(404).json({ error: 'Candidato não encontrado.' });

        const curriculoResult = await pool.query('SELECT candidato_id, resumo_profissional, habilidades, experiencias, formacao_academica, arquivo_nome FROM curriculos WHERE candidato_id = $1', [candidatoResult.rows[0].id]);
        res.json({ curriculo: curriculoResult.rows[0] || null });
    } catch (error) {
        console.error('Erro ao buscar currículo:', error);
        res.status(500).json({ error: 'Erro ao buscar currículo.' });
    }
});

app.post('/api/curriculo', authenticateToken, requireRole('candidato'), async (req, res) => {
    const { resumo_profissional, habilidades, experiencias, formacao_academica, arquivo_nome, arquivo_dados } = req.body;
    try {
        const candidatoResult = await pool.query('SELECT id FROM candidatos WHERE usuario_id = $1', [req.user.id]);
        if (candidatoResult.rows.length === 0) return res.status(404).json({ error: 'Candidato não encontrado.' });

        const candidatoId = candidatoResult.rows[0].id;
        const habArray = Array.isArray(habilidades) ? habilidades : [];

        const query = `
            INSERT INTO curriculos (candidato_id, resumo_profissional, habilidades, experiencias, formacao_academica, arquivo_nome, arquivo_dados)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (candidato_id)
            DO UPDATE SET
                resumo_profissional = EXCLUDED.resumo_profissional,
                habilidades = EXCLUDED.habilidades,
                experiencias = EXCLUDED.experiencias,
                formacao_academica = EXCLUDED.formacao_academica,
                arquivo_nome = COALESCE(EXCLUDED.arquivo_nome, curriculos.arquivo_nome),
                arquivo_dados = COALESCE(EXCLUDED.arquivo_dados, curriculos.arquivo_dados),
                data_atualizacao = NOW()
            RETURNING candidato_id, arquivo_nome;
        `;

        const values = [
            candidatoId,
            resumo_profissional || '',
            habArray,
            experiencias ? JSON.stringify(experiencias) : '[]',
            formacao_academica ? JSON.stringify(formacao_academica) : '[]',
            arquivo_nome || null,
            arquivo_dados || null
        ];

        const result = await pool.query(query, values);
        res.status(200).json({ message: 'Currículo e anexo salvos com sucesso!', curriculo: result.rows[0] });
    } catch (error) {
        console.error('Erro ao salvar currículo:', error);
        res.status(500).json({ error: 'Erro interno ao salvar o currículo.' });
    }
});

// ==========================================
// ROTAS DE INTELIGÊNCIA ARTIFICIAL (GEMINI)
// ==========================================
app.post('/api/ia/processar-curriculo', authenticateToken, requireRole('candidato'), async (req, res) => {
    const { arquivo_dados } = req.body;
    
    if (!arquivo_dados) {
        return res.status(400).json({ error: 'Nenhum arquivo enviado para processamento.' });
    }

    const parsed = parseBase64(arquivo_dados);
    if (!parsed) {
        return res.status(400).json({ error: 'Formato de arquivo base64 inválido.' });
    }

    try {
        const apiKey = process.env.GEMINI_API_KEY;
        if (!apiKey) throw new Error('GEMINI_API_KEY não configurada no ambiente do Render.');

        // Instrução rígida para saída JSON
        const systemInstruction = `Você é o Motor de Inteligência de Carreira. Extraia as informações do currículo anexado. Responda ESTRITAMENTE em formato JSON com a estrutura exata: { "resumo_profissional": "string", "habilidades": ["string"], "experiencias": [{"empresa": "string", "cargo": "string", "ano": "string"}], "formacao_academica": [{"instituicao": "string", "curso": "string", "ano": "string"}] }. Não adicione blocos de marcação markdown (\`\`\`json) ou textos adicionais fora do JSON.`;

        // Payload idêntico para qualquer tentativa
        const payloadData = {
            system_instruction: { parts: [{ text: systemInstruction }] },
            contents: [{
                role: "user",
                parts: [
                    { inline_data: { mime_type: parsed.mimeType, data: parsed.data } },
                    { text: "Extraia os dados estruturados deste currículo." }
                ]
            }],
            generation_config: { response_mime_type: "application/json" }
        };

        // Padrão de Fallback: Tenta o 3.7-flash primeiro, se falhar, tenta o 3.1-pro-preview
        const modelsToTry = ['gemini-3.7-flash', 'gemini-3.1-pro-preview'];
        let geminiData = null;
        let success = false;

        for (const model of modelsToTry) {
            const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;
            try {
                const response = await fetch(url, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payloadData)
                });

                if (response.ok) {
                    geminiData = await response.json();
                    success = true;
                    console.log(`Processamento IA bem-sucedido via modelo: ${model}`);
                    break; // Sai do loop assim que der sucesso
                } else {
                    console.warn(`Tentativa com ${model} falhou com status ${response.status}. Iniciando Fallback...`);
                }
            } catch (networkError) {
                console.error(`Erro de rede ao acessar ${model}:`, networkError);
            }
        }

        if (!success || !geminiData) {
            return res.status(503).json({ error: 'Os servidores da IA do Google estão temporariamente sobrecarregados. Por favor, aguarde alguns instantes e tente novamente.' });
        }

        const extractedText = geminiData.candidates[0].content.parts[0].text;
        const curriculoJSON = JSON.parse(extractedText);

        res.json({
            message: 'Análise multimodal concluída com sucesso.',
            curriculo_extraido: curriculoJSON,
            previous_interaction_id: geminiData.candidates[0].token_count || "idx_initial_state"
        });

    } catch (error) {
        console.error('Erro no processamento da rota de IA:', error);
        res.status(500).json({ error: 'Falha interna ao analisar o currículo com Inteligência Artificial.' });
    }
});

// ==========================================
// ROTAS DE VAGAS
// ==========================================
app.post('/api/vagas', authenticateToken, requireRole('empresa'), async (req, res) => {
    const { titulo, descricao, requisitos, salario_min, salario_max, cidade, estado } = req.body;
    try {
        const empresaResult = await pool.query('SELECT id FROM empresas WHERE usuario_id = $1', [req.user.id]);
        if (empresaResult.rows.length === 0) return res.status(404).json({ error: 'Empresa não encontrada.' });

        const insertVaga = await pool.query(
            `INSERT INTO vagas (empresa_id, titulo, descricao, requisitos, salario_min, salario_max, cidade, estado, tipo_vaga) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'direta') RETURNING *`,
            [empresaResult.rows[0].id, titulo, descricao, requisitos, salario_min, salario_max, cidade, estado]
        );
        res.status(201).json({ message: 'Vaga publicada com sucesso!', vaga: insertVaga.rows[0] });
    } catch (error) {
        console.error('Erro ao publicar vaga:', error);
        res.status(500).json({ error: 'Erro ao cadastrar a vaga.' });
    }
});

app.get('/api/vagas', async (req, res) => {
    const { busca, cidade } = req.query;
    let query = `SELECT v.*, e.nome_fantasia as nome_empresa FROM vagas v LEFT JOIN empresas e ON v.empresa_id = e.id WHERE v.status = 'ativo'`;
    const params = [];
    let paramIndex = 1;

    if (busca) { query += ` AND v.titulo ILIKE $${paramIndex}`; params.push(`%${busca}%`); paramIndex++; }
    if (cidade) { query += ` AND v.cidade ILIKE $${paramIndex}`; params.push(`%${cidade}%`); paramIndex++; }
    query += ' ORDER BY v.data_publicacao DESC';

    try {
        const result = await pool.query(query, params);
        res.json(result.rows);
    } catch (error) {
        console.error('Erro ao buscar vagas:', error);
        res.status(500).json({ error: 'Erro interno ao consultar vagas.' });
    }
});

app.get('/api/empresa/vagas', authenticateToken, requireRole('empresa'), async (req, res) => {
    try {
        const empresaResult = await pool.query('SELECT id FROM empresas WHERE usuario_id = $1', [req.user.id]);
        if (empresaResult.rows.length === 0) return res.status(404).json({ error: 'Empresa não encontrada.' });

        const empresaId = empresaResult.rows[0].id;
        const result = await pool.query('SELECT * FROM vagas WHERE empresa_id = $1 ORDER BY data_publicacao DESC', [empresaId]);

        res.json(result.rows);
    } catch (error) {
        console.error('Erro ao buscar vagas da empresa:', error);
        res.status(500).json({ error: 'Erro interno ao buscar as vagas.' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
