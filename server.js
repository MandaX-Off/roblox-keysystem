const express = require('express');
const cors = require('cors');
const helmet = require('helmet');

const app = express();
app.use(express.json());
app.use(cors());
app.use(helmet());

const PORT = process.env.PORT || 3000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'TOKEN_SUPER_SEGURO_CAMBIA_ESTE';

// Almacenamiento temporal en memoria
let KEYS = [
  { key: 'MANDAX-123', used: false, user: null, revoked: false },
  { key: 'VIP-456', used: false, user: null, revoked: false },
];

// Generador de keys aleatorias
function genKey() {
  return Math.random().toString(36).substring(2, 10).toUpperCase();
}

// ----- Rutas de administrador -----
app.post('/admin/create', (req, res) => {
  const token = req.headers['x-admin-token'];
  if (token !== ADMIN_TOKEN) return res.status(401).json({ error: 'Unauthorized' });

  const newKey = { key: genKey(), used: false, user: null, revoked: false };
  KEYS.push(newKey);
  res.json({ key: newKey.key });
});

app.get('/admin/list', (req, res) => {
  const token = req.headers['x-admin-token'];
  if (token !== ADMIN_TOKEN) return res.status(401).json({ error: 'Unauthorized' });
  res.json({ keys: KEYS });
});

app.post('/admin/revoke', (req, res) => {
  const token = req.headers['x-admin-token'];
  if (token !== ADMIN_TOKEN) return res.status(401).json({ error: 'Unauthorized' });

  const { key } = req.body;
  const k = KEYS.find(k => k.key === key);
  if (!k) return res.status(404).json({ error: 'Key not found' });
  k.revoked = true;
  res.json({ ok: true });
});

// ----- Validación pública (Roblox) -----
app.post('/validate', (req, res) => {
  const { key, username } = req.body;
  const k = KEYS.find(k => k.key === key);

  if (!k) return res.status(404).json({ valid: false, reason: 'Key not found' });
  if (k.revoked) return res.status(403).json({ valid: false, reason: 'Revoked' });
  if (k.used && k.user !== username)
    return res.status(403).json({ valid: false, reason: 'Already used' });

  k.used = true;
  k.user = username;
  res.json({ valid: true, user: username });
});

app.get('/', (req, res) => res.send('Servidor de Keys activo 🔑'));
app.listen(PORT, () => console.log(`✅ Key server running on port ${PORT}`));
