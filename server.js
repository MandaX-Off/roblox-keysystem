const express = require('express');
const bodyParser = require('body-parser');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const cors = require('cors');
const helmet = require('helmet');

const app = express();
const db = new Database('keys.db');
const PORT = process.env.PORT || 3000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'TOKEN_SUPER_SEGURO_CAMBIA_ESTE';

// Seguridad básica
app.use(bodyParser.json());
app.use(cors());
app.use(helmet());

// Crear tabla si no existe
db.prepare(`CREATE TABLE IF NOT EXISTS keys (
  key TEXT PRIMARY KEY,
  used INTEGER DEFAULT 0,
  user TEXT DEFAULT NULL,
  created_at INTEGER DEFAULT (strftime('%s','now')),
  revoked INTEGER DEFAULT 0
);`).run();

// Generador de keys aleatorias
function genKey() {
  return crypto.randomBytes(8).toString('hex');
}

// ----- Rutas de administrador -----
app.post('/admin/create', (req, res) => {
  const token = req.headers['x-admin-token'];
  if (token !== ADMIN_TOKEN) return res.status(401).json({ error: 'Unauthorized' });

  const key = genKey();
  db.prepare('INSERT INTO keys (key) VALUES (?)').run(key);
  res.json({ key });
});

app.get('/admin/list', (req, res) => {
  const token = req.headers['x-admin-token'];
  if (token !== ADMIN_TOKEN) return res.status(401).json({ error: 'Unauthorized' });

  const keys = db.prepare('SELECT * FROM keys').all();
  res.json({ keys });
});

app.post('/admin/revoke', (req, res) => {
  const token = req.headers['x-admin-token'];
  if (token !== ADMIN_TOKEN) return res.status(401).json({ error: 'Unauthorized' });

  const { key } = req.body;
  db.prepare('UPDATE keys SET revoked=1 WHERE key=?').run(key);
  res.json({ ok: true });
});

// ----- Ruta pública (para Roblox) -----
app.post('/validate', (req, res) => {
  const { key, username } = req.body;
  if (!key) return res.status(400).json({ valid: false, reason: 'Missing key' });

  const data = db.prepare('SELECT * FROM keys WHERE key=?').get(key);
  if (!data) return res.status(404).json({ valid: false, reason: 'Key not found' });
  if (data.revoked) return res.status(403).json({ valid: false, reason: 'Revoked' });
  if (data.used && data.user !== username)
    return res.status(403).json({ valid: false, reason: 'Already used' });

  db.prepare('UPDATE keys SET used=1, user=? WHERE key=?').run(username, key);
  res.json({ valid: true, user: username });
});

app.listen(PORT, () => console.log(`✅ Key server running on port ${PORT}`));
