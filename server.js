const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
require('dotenv').config();

const { OAuth2Client } = require('google-auth-library');
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const app = express();
app.use(cors());
app.use(bodyParser.json());

const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';

async function getDB() {
  return mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 3306,
    waitForConnections: true,
    connectionLimit: 10
  });
}

function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ error: 'No token' });
  const t = h.split(' ')[1];
  try {
    req.user = jwt.verify(t, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Token inválido' });
  }
}

function admin(req, res, next) {
  if (!req.user || req.user.rol !== 'admin') return res.status(403).json({ error: 'Solo administradores' });
  next();
}

app.get('/', (req, res) => res.send('SportLike backend activo'));

app.post('/api/register', async (req, res) => {
  const { nombre, apellidoP, apellidoM, fechaNac, correo, telefono, usuario, password, rol } = req.body;

  if (!nombre || !apellidoP || !usuario || !password || !correo)
    return res.status(400).json({ error: 'Faltan datos' });

  if (password.length < 6)
    return res.status(400).json({ error: 'Contraseña débil' });

  try {
    const db = await getDB();
    const [exists] = await db.execute(
      'SELECT id FROM users WHERE usuario=? OR correo=?',
      [usuario, correo]
    );

    if (exists.length > 0)
      return res.status(400).json({ error: 'Usuario o correo ya registrado' });

    const hash = await bcrypt.hash(password, 10);

    const [result] = await db.execute(
      'INSERT INTO users (nombre, apellidoP, apellidoM, fechaNac, correo, telefono, usuario, password, rol, verificado) VALUES (?,?,?,?,?,?,?,?,?,?)',
      [nombre, apellidoP, apellidoM || null, fechaNac || null, correo, telefono || null, usuario, hash, rol || 'cliente', 1]
    );

    res.json({ message: 'Registro exitoso' });
  } catch (e) {
    res.status(500).json({ error: 'Error al registrar' });
  }
});

app.post('/api/login', async (req, res) => {
  const { usuario, password } = req.body;

  try {
    const db = await getDB();
    const [rows] = await db.execute('SELECT * FROM users WHERE usuario=?', [usuario]);

    if (rows.length === 0)
      return res.status(400).json({ error: 'Usuario no encontrado' });

    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password);

    if (!ok)
      return res.status(400).json({ error: 'Contraseña incorrecta' });

    const token = jwt.sign(
      { id: user.id, usuario: user.usuario, rol: user.rol },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      user: { id: user.id, nombre: user.nombre, usuario: user.usuario, rol: user.rol, correo: user.correo },
      token
    });
  } catch (e) {
    res.status(500).json({ error: 'Error en login' });
  }
});

app.post('/api/google-login', async (req, res) => {
  const { credential } = req.body;
  if (!credential) return res.status(400).json({ error: 'Sin credenciales' });

  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();
    const correo = payload.email;
    const nombre = payload.name;
    const usuario = correo.split('@')[0];

    const db = await getDB();
    const [rows] = await db.execute('SELECT * FROM users WHERE correo=?', [correo]);

    let user;

    if (rows.length === 0) {
      const [result] = await db.execute(
        'INSERT INTO users (nombre, correo, usuario, password, rol, verificado) VALUES (?,?,?,?,?,?)',
        [nombre, correo, usuario, null, 'cliente', 1]
      );
      user = { id: result.insertId, nombre, correo, usuario, rol: 'cliente' };
    } else {
      user = rows[0];
    }

    const token = jwt.sign(
      { id: user.id, usuario: user.usuario, rol: user.rol },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({ user, token });
  } catch (e) {
    res.status(500).json({ error: 'Error al iniciar con Google' });
  }
});

app.get('/api/users', auth, admin, async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute('SELECT id, nombre, correo, usuario, rol FROM users');
    res.json(rows);
  } catch {
    res.status(500).json({ error: 'Error al obtener usuarios' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log('Backend listo'));
