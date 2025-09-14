
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const Database = require('better-sqlite3');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 8080;

const DEFAULT_DB = path.join(__dirname, 'db', 'usuarios.db');
const DB_PATH = process.env.DB_PATH || DEFAULT_DB;

// --- Preparar base de datos en disco ---
try {
  const targetDir = path.dirname(DB_PATH);
  if (!fs.existsSync(targetDir)) fs.mkdirSync(targetDir, { recursive: true });
  if (!fs.existsSync(DB_PATH) && fs.existsSync(DEFAULT_DB)) {
    fs.copyFileSync(DEFAULT_DB, DB_PATH);
    console.log(`📦 Copiada base de datos a ${DB_PATH}`);
  }
} catch (e) {
  console.warn('No se pudo preparar la DB:', e?.message || e);
}

// --- Conexión SQLite ---
let db;
try {
  db = new Database(DB_PATH);
  console.log(`🗄️  Conectado a SQLite en: ${DB_PATH}`);
} catch (e) {
  console.error('Error abriendo la base de datos:', e);
  process.exit(1);
}

app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- Session store reutilizable (para poder destruir sesiones previas) ---
const sessionStore = new SQLiteStore({
  db: 'sessions.db',
  dir: path.dirname(DB_PATH),
});

app.use(session({
  store: sessionStore,
  secret: process.env.SESSION_SECRET || 'clave-secreta',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 6 // 6 horas
  }
}));

// --- Utilidades para detectar tabla/columna de usuarios ---
function resolveUserLookup(db) {
  const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map(r => r.name);
  const tableCandidates = ["users", "usuarios"];
  const columnCandidates = ["username", "usuario", "nombre"];
  for (const t of tableCandidates) {
    if (!tables.includes(t)) continue;
    const cols = db.prepare(`PRAGMA table_info(${t})`).all().map(c => c.name);
    const hit = columnCandidates.find(c => cols.includes(c));
    if (hit) return { table: t, column: hit };
  }
  return null;
}

// Resolver al arrancar (y cachear)
let USER_LOOKUP = null;
try {
  USER_LOOKUP = resolveUserLookup(db);
  if (!USER_LOOKUP) {
    console.error("❌ No se encontró tabla/columna de usuarios válida. Revisa tu BD.");
  } else {
    console.log(`✅ Login usando tabla '${USER_LOOKUP.table}', columna '${USER_LOOKUP.column}'`);
    // Asegurar columna session_id
    const cols = db.prepare(`PRAGMA table_info(${USER_LOOKUP.table})`).all().map(c => c.name);
    if (!cols.includes('session_id')) {
      db.prepare(`ALTER TABLE ${USER_LOOKUP.table} ADD COLUMN session_id TEXT`).run();
      console.log(`🛠️ Añadida columna session_id en ${USER_LOOKUP.table}`);
    }
  }
} catch (e) {
  console.error("❌ Error resolviendo esquema de usuarios:", e);
}

// --- Middleware: sesión única ---
app.use((req, res, next) => {
  try {
    if (!req.session?.usuario || !USER_LOOKUP) return next();
    const { table, column } = USER_LOOKUP;
    const row = db.prepare(`SELECT session_id FROM ${table} WHERE ${column} = ?`).get(req.session.usuario);
    if (row?.session_id && row.session_id !== req.sessionID) {
      // Esta sesión ha sido reemplazada desde otro dispositivo
      return req.session.destroy(() => res.redirect('/login.html?error=sesion'));
    }
    next();
  } catch (e) {
    console.error('Middleware sesión única:', e);
    next();
  }
});

// --- Inicio (protegido) ---
app.get('/', (req, res) => {
  if (!req.session.usuario) return res.redirect('/login.html');
  res.sendFile(path.join(__dirname, 'public', 'inicio.html'));
});

// --- LOGIN con autodetección + reemplazo de sesión previa ---
app.post('/login', (req, res) => {
  try {
    let { usuario } = req.body;
    usuario = (usuario || '').trim();
    if (!usuario) return res.redirect('/login.html?error=campos');

    if (!USER_LOOKUP) {
      USER_LOOKUP = resolveUserLookup(db);
      if (!USER_LOOKUP) {
        console.error("❌ Esquema no válido: no hay tabla/columna de usuarios.");
        return res.redirect('/login.html?error=server');
      }
    }

    const { table, column } = USER_LOOKUP;
    const row = db.prepare(
      `SELECT ${column} AS username, session_id FROM ${table} WHERE ${column} = ? LIMIT 1`
    ).get(usuario);

    if (!row) return res.redirect('/login.html?error=credenciales');

    // ¿Existe una sesión previa distinta?
    if (row.session_id && row.session_id !== req.sessionID) {
      // Opción B (recomendada): INVALIDAR la anterior y continuar
      sessionStore.destroy(row.session_id, (err) => {
        if (err) console.warn('No se pudo destruir la sesión previa:', err);
        // Vincular nueva sesión
        req.session.usuario = row.username;
        db.prepare(`UPDATE ${table} SET session_id = ? WHERE ${column} = ?`).run(req.sessionID, row.username);
        return res.redirect('/');
      });
      return;
      // Opción A (alternativa): BLOQUEAR el login nuevo
      // return res.redirect('/login.html?error=sesion');
    }

    // No había sesión previa o es la misma => vincular
    req.session.usuario = row.username;
    db.prepare(`UPDATE ${table} SET session_id = ? WHERE ${column} = ?`).run(req.sessionID, row.username);
    return res.redirect('/');

  } catch (e) {
    console.error("❌ Error DB /login:", e);
    return res.redirect('/login.html?error=server');
  }
});

// --- Logout: limpiar marca de sesión ---
app.get('/logout', (req, res) => {
  try {
    if (req.session?.usuario && USER_LOOKUP) {
      const { table, column } = USER_LOOKUP;
      db.prepare(`UPDATE ${table} SET session_id = NULL WHERE ${column} = ?`).run(req.session.usuario);
    }
  } catch (e) {
    console.warn('No se pudo limpiar session_id en logout:', e);
  }
  req.session.destroy(() => res.redirect('/login.html'));
});

// --- Utilidad para el frontend ---
app.get('/verificar-sesion', (req, res) => {
  res.json({ activo: !!req.session.usuario });
});

// --- 404 ---
app.use((req, res) => res.status(404).send('Página no encontrada'));

app.listen(PORT, () => console.log(`🚀 Servidor corriendo en el puerto ${PORT}`));
