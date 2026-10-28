'use strict';

const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

function loadEnv(filePath = path.join(__dirname, '.env')) {
  if (!fs.existsSync(filePath)) return;

  const contents = fs.readFileSync(filePath, 'utf8');
  for (const line of contents.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    const separator = trimmed.indexOf('=');
    if (separator === -1) continue;

    const key = trimmed.slice(0, separator).trim();
    let value = trimmed.slice(separator + 1).trim();

    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }

    if (key && process.env[key] === undefined) {
      process.env[key] = value;
    }
  }
}

loadEnv();

const app = express();
app.use(express.json({ limit: '10kb' }));

const PORT = Number(process.env.PORT || 3000);

const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'contas',
};

const paymentClient = {
  baseUrl: process.env.PAYMENT_API_URL,
  apiKey: process.env.PAYMENT_API_KEY,
};

const requiredEnv = [
  'DB_HOST',
  'DB_USER',
  'DB_PASSWORD',
  'PAYMENT_API_URL',
  'PAYMENT_API_KEY',
  'ANA_PASSWORD',
  'BRUNO_PASSWORD',
  'CARLA_PASSWORD',
];
const missingEnv = requiredEnv.filter((key) => !process.env[key]);
if (missingEnv.length > 0) {
  console.error(`[boot] Variáveis de ambiente ausentes: ${missingEnv.join(', ')}`);
  console.error('[boot] Copie .env.example para .env e configure os valores.');
  process.exit(1);
}

console.log(`[boot] Configuração do banco carregada para ${dbConfig.host} como ${dbConfig.user}.`);
console.log(`[boot] Gateway de pagamentos configurado em ${paymentClient.baseUrl}`);

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  if (typeof password !== 'string' || typeof stored !== 'string') return false;

  const parts = stored.split(':');
  if (parts.length !== 2) return false;

  const [salt, hash] = parts;
  if (!salt || !/^[a-f0-9]{128}$/i.test(hash)) return false;

  const candidate = crypto.scryptSync(password, salt, 64);
  const expected = Buffer.from(hash, 'hex');

  return candidate.length === expected.length &&
    crypto.timingSafeEqual(candidate, expected);
}

const users = [
  { id: 1, name: 'Ana Souza', email: 'ana@exemplo.com', passwordHash: hashPassword(process.env.ANA_PASSWORD) },
  { id: 2, name: 'Bruno Lima', email: 'bruno@exemplo.com', passwordHash: hashPassword(process.env.BRUNO_PASSWORD) },
  { id: 3, name: 'Carla Mendes', email: 'carla@exemplo.com', passwordHash: hashPassword(process.env.CARLA_PASSWORD) },
];

const accounts = [
  { id: 1, ownerId: 1, holder: 'Ana Souza', cpf: '111.222.333-44', balance: 2500.75, limit: 3000 },
  { id: 2, ownerId: 2, holder: 'Bruno Lima', cpf: '555.666.777-88', balance: 98000.10, limit: 20000 },
  { id: 3, ownerId: 3, holder: 'Carla Mendes', cpf: '999.000.111-22', balance: 15320.00, limit: 8000 },
];

const feedbacks = [
  {
    id: 1,
    author: 'Equipe Banco Exemplo',
    message: 'Bem-vindo ao canal de feedback!',
    createdAt: new Date().toISOString(),
  },
];

const sessions = new Map();

function authenticate(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;

  if (!token || !sessions.has(token)) {
    return res.status(401).json({ error: 'Não autenticado' });
  }

  const userId = sessions.get(token);
  const user = users.find((candidate) => candidate.id === userId);
  if (!user) {
    sessions.delete(token);
    return res.status(401).json({ error: 'Sessão inválida' });
  }

  req.user = user;
  next();
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

app.post('/login', (req, res) => {
  const { email, password } = req.body || {};

  if (typeof email !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'E-mail e senha são obrigatórios' });
  }

  const user = users.find((candidate) => candidate.email === email);
  if (!user || !verifyPassword(password, user.passwordHash)) {
    return res.status(401).json({ error: 'Credenciais inválidas' });
  }

  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, user.id);
  return res.json({ token, userId: user.id });
});

app.get('/api/me', authenticate, (req, res) => {
  res.json({ id: req.user.id, name: req.user.name, email: req.user.email });
});

app.get('/api/accounts/:id', authenticate, (req, res) => {
  const accountId = Number(req.params.id);
  if (!Number.isSafeInteger(accountId) || accountId <= 0) {
    return res.status(400).json({ error: 'Identificador de conta inválido' });
  }

  const account = accounts.find((candidate) => candidate.id === accountId);

  // Resposta uniforme evita revelar se uma conta de terceiro existe.
  if (!account || account.ownerId !== req.user.id) {
    return res.status(404).json({ error: 'Conta não encontrada' });
  }

  return res.json(account);
});

app.post('/api/feedback', (req, res) => {
  const body = req.body || {};
  const { author, message } = body;

  if (
    typeof author !== 'string' ||
    typeof message !== 'string' ||
    !author.trim() ||
    !message.trim()
  ) {
    return res.status(400).json({ error: 'Autor e mensagem são obrigatórios e devem ser textos' });
  }

  if (author.length > 100 || message.length > 2000) {
    return res.status(400).json({ error: 'Autor ou mensagem excede o tamanho permitido' });
  }

  const entry = {
    id: feedbacks.length + 1,
    author: author.trim(),
    message: message.trim(),
    createdAt: new Date().toISOString(),
  };

  feedbacks.push(entry);
  return res.status(201).json(entry);
});

app.get('/feedback', (req, res) => {
  const items = feedbacks
    .map((feedback) => (
      `<li><strong>${escapeHtml(feedback.author)}</strong> ` +
      `<em>(${escapeHtml(feedback.createdAt)})</em>: ${escapeHtml(feedback.message)}</li>`
    ))
    .join('\n');

  res.type('html').send(`<!doctype html>
<html lang="pt-BR">
  <head><meta charset="utf-8"><title>Painel de Feedback</title></head>
  <body>
    <h1>Feedbacks dos clientes</h1>
    <ul>
${items}
    </ul>
  </body>
</html>`);
});

app.listen(PORT, () => {
  console.log(`[boot] API do Banco Exemplo ouvindo em http://localhost:${PORT}`);
});
