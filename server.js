// servidor Express con control de sesión única por usuario
const path = require('path');
const fs = require('fs');
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const cors = require('cors');
const Database = require('better-sqlite3');
require('dotenv').config();

const app = express();

// Configuración
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-secret';
const SESS_DIR = process.env.SESS_DIR || path.join(__dirname, '.data');
const SESS_DB = process.env.SESS_DB || 'sessions.sqlite';

// Asegurar carpeta de sesiones
fs.mkdirSync(SESS_DIR, { recursive: true });

// Middlewares
app.use(cors({
  origin: process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',') : true,
  credentials: true
}));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
  store: new SQLiteStore({ dir: SESS_DIR, db: SESS_DB }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 7 * 24 * 60 * 60 * 1000,
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    secure: process.env.NODE_ENV === 'production'
  }
}));

// --- Single-session por usuario ---
const sessDBPath = path.join(SESS_DIR, 'app.sqlite');
const appDb = new Database(sessDBPath);
appDb.pragma('journal_mode = WAL');
appDb.exec(`
  CREATE TABLE IF NOT EXISTS active_sessions (
    user_id TEXT PRIMARY KEY,
    sid TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );
`);

function setActiveSession(userId, sid) {
  const tx = appDb.transaction((uid, s) => {
    const row = appDb.prepare('SELECT sid FROM active_sessions WHERE user_id = ?').get(uid);
    if (!row) {
      appDb.prepare('INSERT INTO active_sessions (user_id, sid, updated_at) VALUES (?, ?, datetime("now"))').run(uid, s);
    } else {
      appDb.prepare('UPDATE active_sessions SET sid = ?, updated_at = datetime("now") WHERE user_id = ?').run(s, uid);
    }
  });
  tx(userId, sid);
}

function getActiveSession(userId) {
  const row = appDb.prepare('SELECT sid FROM active_sessions WHERE user_id = ?').get(userId);
  return row ? row.sid : null;
}

function clearActiveSession(userId, sidToClear = null) {
  if (sidToClear) {
    const current = getActiveSession(userId);
    if (current === sidToClear) {
      appDb.prepare('DELETE FROM active_sessions WHERE user_id = ?').run(userId);
    }
  } else {
    appDb.prepare('DELETE FROM active_sessions WHERE user_id = ?').run(userId);
  }
}

function enforceSingleSession(req, res, next) {
  if (req.session && req.session.user && req.session.user.id) {
    const activeSid = getActiveSession(req.session.user.id);
    if (activeSid && activeSid !== req.sessionID) {
      req.session.destroy(() => {
        res.status(403).json({ error: 'Tu sesión fue iniciada en otro dispositivo/ventana. Vuelve a entrar.' });
      });
      return;
    }
  }
  next();
}
app.use(enforceSingleSession);

// --- Rutas de ejemplo ---
// Ruta de login (ejemplo)
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  // TODO: valida usuario real
  if (email === 'demo' && password === 'demo') {
    const user = { id: 'demo', email };
    const prevSid = getActiveSession(user.id);
    if (prevSid && prevSid !== req.sessionID) {
      req.sessionStore.destroy(prevSid, (err) => {
        if (err) console.error('No se pudo destruir la sesión previa:', err);
      });
    }
    req.session.user = user;
    setActiveSession(user.id, req.sessionID);
    return res.json({ ok: true, user });
  }
  res.status(401).json({ error: 'Credenciales inválidas' });
});

// Ruta de logout
app.post('/logout', (req, res) => {
  const userId = req.session?.user?.id;
  const sid = req.sessionID;
  req.session.destroy(() => {
    if (userId) clearActiveSession(userId, sid);
    res.json({ ok: true });
  });
});

// Salud
app.get('/health', (_req, res) => {
  res.json({ ok: true, ts: new Date().toISOString() });
});

// Static (si existe ./public)
const publicDir = path.join(__dirname, 'public');
if (fs.existsSync(publicDir)) {
  app.use(express.static(publicDir));
  app.get('/', (_req, res) => {
    res.sendFile(path.join(publicDir, 'index.html'));
  });
} else {
  app.get('/', (_req, res) => res.send('OK'));
}

// Arrancar servidor
app.listen(PORT, () => {
  console.log(`Servidor escuchando en http://localhost:${PORT}`);
});
