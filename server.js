// server.js
const express = require('express');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');

const app = express();
app.use(express.json());
app.use(cors());
app.use(helmet());

const PORT = process.env.PORT || 3000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'CAMBIA_AQUI_TU_TOKEN';

const DB_FILE = path.join(__dirname, 'keys.json');

// Cargar keys desde archivo (o crear si no existe)
function loadKeys() {
  try {
    if (!fs.existsSync(DB_FILE)) {
      fs.writeFileSync(DB_FILE, JSON.stringify([]));
    }
    const raw = fs.readFileSync(DB_FILE, 'utf8');
    return JSON.parse(raw || '[]');
  } catch (e) {
    console.error('Error leyendo keys.json', e);
    return [];
  }
}

function saveKeys(keys) {
  // Escritura atomica simple
  fs.writeFileSync(DB_FILE, JSON.stringify(keys, null, 2));
}

let KEYS = loadKeys();

// Generador simple
function genKey() {
  return Math.random().toString(36).substring(2, 10).toUpperCase();
}

// ADMIN: crear key
app.post('/admin/create', (req, res) => {
  const token = req.headers['x-admin-token'];
  if (token !== ADMIN_TOKEN) return res.status(401).json({ error: 'Unauthorized' });

  const newKey = { key: genKey(), used: false, user: null, revoked: false, created_at: Date.now() };
  KEYS.push(newKey);
  saveKeys(KEYS);
  return res.json({ ok: true, key: newKey.key });
});

// ADMIN: listar
app.get('/admin/list', (req, res) => {
  const token = req.headers['x-admin-token'];
  if (token !== ADMIN_TOKEN) return res.status(401).json({ error: 'Unauthorized' });
  return res.json({ ok: true, keys: KEYS });
});

// ADMIN: revoke
app.post('/admin/revoke', (req, res) => {
  const token = req.headers['x-admin-token'];
  if (token !== ADMIN_TOKEN) return res.status(401).json({ error: 'Unauthorized' });
  const { key } = req.body;
  const k = KEYS.find(x => x.key === key);
  if (!k) return res.status(404).json({ ok:false, error: 'Key not found' });
  k.revoked = true;
  saveKeys(KEYS);
  return res.json({ ok: true });
});

// PUBLIC: validate (Roblox - servidor Roblox hará la petición)
app.post('/validate', (req, res) => {
  const { key, username } = req.body;
  if (!key) return res.status(400).json({ valid: false, reason: 'Missing key' });

  const k = KEYS.find(x => x.key === key);
  if (!k) return res.status(404).json({ valid: false, reason: 'Key not found' });
  if (k.revoked) return res.status(403).json({ valid: false, reason: 'Revoked' });
  if (k.used && k.user !== username) return res.status(403).json({ valid: false, reason: 'Already used' });

  // Marca como usada y persiste
  k.used = true;
  k.user = username || null;
  k.used_at = Date.now();
  saveKeys(KEYS);

  return res.json({ valid: true, user: k.user });
});

app.get('/', (req, res) => res.send('Servidor de Keys activo 🔑'));
app.listen(PORT, () => console.log(`Server listening on ${PORT}`));
