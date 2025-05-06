const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const session = require('express-session');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Configuração do Supabase
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// Middlewares
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
  secret: process.env.SESSION_SECRET || 'chave-secreta',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax'
  }
}));

// Validação de senha forte
function senhaEhForte(senha) {
  const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@#$%!&*])[A-Za-z\d@#$%!&*]{8,}$/;
  return regex.test(senha);
}

// Rota de cadastro
app.post('/cadastro', async (req, res) => {
  const { email, username, password } = req.body;

  if (!senhaEhForte(password)) {
    return res.json({
      success: false,
      message: 'A senha deve conter no mínimo 8 caracteres, uma letra maiúscula, minúscula, número e símbolo.'
    });
  }

  try {
    // Verificar se o email já existe
    const { data: existingUser } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single();

    if (existingUser) {
      return res.json({ success: false, message: 'E-mail já cadastrado.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    // Inserir novo usuário
    const { error } = await supabase
      .from('users')
      .insert([
        {
          email,
          username,
          password: hashedPassword,
          is_admin: false
        }
      ]);

    if (error) throw error;

    req.session.username = username;
    req.session.isAdmin = false;
    res.json({ success: true });
  } catch (error) {
    console.error('Erro:', error);
    res.json({ success: false, message: 'Erro ao cadastrar.' });
  }
});

// Rota de login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const { data: users, error } = await supabase
      .from('users')
      .select('*')
      .or(`username.eq.${username},email.eq.${username}`)
      .single();

    if (error || !users) {
      return res.json({ success: false, message: 'Usuário ou e-mail não encontrado.' });
    }

    const match = await bcrypt.compare(password, users.password);
    if (!match) {
      return res.json({ success: false, message: 'Senha incorreta.' });
    }

    req.session.username = users.username;
    req.session.isAdmin = !!users.is_admin;

    res.json({
      success: true,
      redirect: users.is_admin ? '/admin.html' : '/index.html'
    });
  } catch (error) {
    console.error('Erro:', error);
    res.json({ success: false, message: 'Erro ao fazer login.' });
  }
});

// Sessão
app.get('/session-info', (req, res) => {
  res.json({
    loggedIn: !!req.session.username,
    username: req.session.username,
    isAdmin: req.session.isAdmin
  });
});

// Conteúdo: Adicionar
app.post('/add-conteudo', async (req, res) => {
  const { cover, title, release, duration, type } = req.body;
  const nomeCompleto = `${title} (${release})`;

  try {
    const { error } = await supabase
      .from('conteudo')
      .insert([
        {
          capa: cover,
          nome: nomeCompleto,
          data_lancamento: release,
          duracao: duration,
          tipo: type
        }
      ]);

    if (error) throw error;
    res.json({ success: true });
  } catch (error) {
    console.error('Erro:', error);
    res.json({ success: false, message: 'Erro ao adicionar conteúdo.' });
  }
});

// Conteúdo: Listar
app.get('/conteudo', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('conteudo')
      .select('*');

    if (error) throw error;
    res.json(data);
  } catch (error) {
    console.error('Erro:', error);
    res.status(500).json({ error: 'Erro ao buscar conteúdo.' });
  }
});

// Configuração para o Netlify
if (process.env.NODE_ENV === 'production') {
  app.use(express.static('public'));
  
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  });
}

// Inicia servidor
app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});
