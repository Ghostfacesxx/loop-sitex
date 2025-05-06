const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

exports.handler = async (event, context) => {
  // Configurar CORS
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE'
  };

  // Lidar com preflight requests
  if (event.httpMethod === 'OPTIONS') {
    return {
      statusCode: 200,
      headers,
      body: ''
    };
  }

  try {
    const path = event.path.replace('/.netlify/functions/api/', '');
    const method = event.httpMethod;
    const body = event.body ? JSON.parse(event.body) : {};

    // Rotas
    switch (path) {
      case 'conteudo':
        if (method === 'GET') {
          const { data, error } = await supabase
            .from('conteudo')
            .select('*');
          
          if (error) throw error;
          
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(data)
          };
        }
        break;

      case 'cadastro':
        if (method === 'POST') {
          const { email, username, password } = body;
          
          const { data: existingUser } = await supabase
            .from('users')
            .select('*')
            .eq('email', email)
            .single();

          if (existingUser) {
            return {
              statusCode: 400,
              headers,
              body: JSON.stringify({ success: false, message: 'E-mail já cadastrado.' })
            };
          }

          const hashedPassword = await bcrypt.hash(password, 10);
          
          const { error } = await supabase
            .from('users')
            .insert([{
              email,
              username,
              password: hashedPassword,
              is_admin: false
            }]);

          if (error) throw error;

          return {
            statusCode: 200,
            headers,
            body: JSON.stringify({ success: true })
          };
        }
        break;

      case 'login':
        if (method === 'POST') {
          const { username, password } = body;

          const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .or(`username.eq.${username},email.eq.${username}`)
            .single();

          if (error || !user) {
            return {
              statusCode: 400,
              headers,
              body: JSON.stringify({ success: false, message: 'Usuário não encontrado.' })
            };
          }

          const match = await bcrypt.compare(password, user.password);
          if (!match) {
            return {
              statusCode: 400,
              headers,
              body: JSON.stringify({ success: false, message: 'Senha incorreta.' })
            };
          }

          return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
              success: true,
              redirect: user.is_admin ? '/admin.html' : '/index.html'
            })
          };
        }
        break;
    }

    return {
      statusCode: 404,
      headers,
      body: JSON.stringify({ message: 'Rota não encontrada' })
    };

  } catch (error) {
    console.error('Erro:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ message: 'Erro interno do servidor' })
    };
  }
}; 