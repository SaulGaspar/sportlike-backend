const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const nodemailer = require('nodemailer');
require('dotenv').config();

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
    connectionLimit: 10,
    queueLimit: 0
  });
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'No token' });
  const parts = auth.split(' ');
  if (parts.length !== 2) return res.status(401).json({ error: 'Token error' });
  const token = parts[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Token inválido' });
  }
}

function adminOnly(req, res, next) {
  if (!req.user || req.user.rol !== 'admin') return res.status(403).json({ error: 'Solo administradores' });
  next();
}

app.get('/', (req, res) => {
  res.send('Servidor SportLike funcionando correctamente');
});

app.post('/api/register', async (req, res) => {
  const { nombre, apellidoP, apellidoM, fechaNac, correo, telefono, usuario, password, rol } = req.body;
  if (!nombre || !apellidoP || !usuario || !password || !correo)
    return res.status(400).json({ error: 'Faltan campos requeridos' });
  if (password.length < 6) return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(correo)) return res.status(400).json({ error: 'Correo inválido' });

  try {
    const db = await getDB();
    const [existing] = await db.execute(
      'SELECT id FROM users WHERE usuario = ? OR correo = ? OR telefono = ?',
      [usuario, correo, telefono]
    );
    if (existing.length > 0) return res.status(400).json({ error: 'Usuario, correo o teléfono ya registrado' });

    const hash = await bcrypt.hash(password, 10);
    const [result] = await db.execute(
      'INSERT INTO users (nombre, apellidoP, apellidoM, fechaNac, correo, telefono, usuario, password, rol, verificado) VALUES (?,?,?,?,?,?,?,?,?,0)',
      [nombre, apellidoP, apellidoM || null, fechaNac || null, correo, telefono || null, usuario, hash, rol || 'cliente']
    );

    const token = jwt.sign({ id: result.insertId, correo }, JWT_SECRET, { expiresIn: '1d' });
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: process.env.EMAIL_PORT,
      secure: false,
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
    });

    const verifyLink = `${process.env.CLIENT_URL}/verify-email?token=${token}`;
    await transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to: correo,
      subject: 'Verifica tu correo - SportLike',
      html: `<p>Hola ${nombre},</p>
             <p>Gracias por registrarte en SportLike. Para activar tu cuenta, haz clic en el siguiente enlace:</p>
             <a href="${verifyLink}">Verificar correo</a>
             <p>Si no creaste esta cuenta, ignora este correo.</p>`
    });

    res.json({ message: 'Usuario registrado correctamente. Revisa tu correo para verificar la cuenta.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error registrando usuario', details: err.message });
  }
});

// LOGIN
app.post('/api/login', async (req, res) => {
  const { usuario, password } = req.body;
  try {
    const db = await getDB();
    const [rows] = await db.execute('SELECT * FROM users WHERE usuario = ?', [usuario]);
    if (rows.length === 0) return res.status(401).json({ error: 'Usuario no encontrado' });

    const user = rows[0];
    if (user.verificado === 0) return res.status(403).json({ error: 'Debes verificar tu correo antes de iniciar sesión' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Contraseña incorrecta' });

    const token = jwt.sign({ id: user.id, usuario: user.usuario, rol: user.rol }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ user: { id: user.id, nombre: user.nombre, usuario: user.usuario, rol: user.rol, correo: user.correo }, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error en login' });
  }
});

// Ruta de prueba para verificar conexión con la base de datos
app.get('/api/testdb', async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute('SELECT NOW() AS fecha');
    res.json({ ok: true, fecha: rows[0].fecha });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});


// VERIFICACIÓN EMAIL
app.get('/api/verify-email', async (req, res) => {
  const token = req.query.token;
  if (!token) return res.status(400).send('Token inválido');

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const db = await getDB();
    await db.execute('UPDATE users SET verificado = 1 WHERE id = ?', [decoded.id]);
    res.send('Correo verificado correctamente. Ahora puedes iniciar sesión.');
  } catch {
    res.status(400).send('Token inválido o expirado');
  }
});

// OBTENER TODOS LOS USUARIOS (SOLO ADMIN)
app.get('/api/users', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute('SELECT id, nombre, apellidoP, apellidoM, correo, usuario, rol FROM users');
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error al obtener usuarios' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Servidor corriendo en http://localhost:${PORT}`));
