const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
require('dotenv').config();

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(passport.initialize());

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

function generarPasswordAleatoria(longitud = 10) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%&*';
  let pass = '';
  for (let i = 0; i < longitud; i++) {
    pass += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return pass;
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'No token' });
  const token = auth.split(' ')[1];
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

passport.use(new GoogleStrategy(
  {
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      const db = await getDB();
      const correo = profile.emails[0].value;
      const [rows] = await db.execute('SELECT * FROM users WHERE correo = ?', [correo]);
      let user;
      if (rows.length > 0) {
        user = rows[0];
      } else {
        const tempPassword = generarPasswordAleatoria();
        const hash = await bcrypt.hash(tempPassword, 10);
        const [result] = await db.execute(
          `INSERT INTO users 
            (nombre, correo, usuario, password, rol, verificado, createdAt, updatedAt)
           VALUES (?,?,?,?,?,1,NOW(),NOW())`,
          [profile.displayName, correo, profile.id, hash, 'cliente']
        );
        user = { id: result.insertId, nombre: profile.displayName, correo, usuario: profile.id, rol: 'cliente' };
      }
      const token = jwt.sign(
        { id: user.id, usuario: user.usuario, rol: user.rol, correo: user.correo, nombre: user.nombre },
        JWT_SECRET,
        { expiresIn: '7d' }
      );
      done(null, token);
    } catch (err) {
      done(err, null);
    }
  }
));

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { session: false }), (req, res) => {
  const token = req.user;
  res.redirect(`${process.env.CLIENT_URL}/google-callback?token=${token}`);
});

app.get('/', (req, res) => res.send('Servidor SportLike funcionando correctamente'));

app.post('/api/register', async (req, res) => {
  const { nombre, apellidoP, apellidoM, fechaNac, correo, telefono, usuario, rol } = req.body;
  if (!nombre || !apellidoP || !usuario || !correo) return res.status(400).json({ error: 'Faltan campos requeridos' });
  try {
    const db = await getDB();
    const [existing] = await db.execute(
      'SELECT id FROM users WHERE usuario = ? OR correo = ? OR telefono = ?',
      [usuario, correo, telefono || null]
    );
    if (existing.length > 0) return res.status(400).json({ error: 'Usuario, correo o teléfono ya registrado' });

    const hash = await bcrypt.hash(generarPasswordAleatoria(), 10);
    const [result] = await db.execute(
      `INSERT INTO users 
        (nombre, apellidoP, apellidoM, fechaNac, correo, telefono, usuario, password, rol, verificado, createdAt, updatedAt)
       VALUES (?,?,?,?,?,?,?,?,?,0,NOW(),NOW())`,
      [nombre, apellidoP, apellidoM || null, fechaNac || null, correo, telefono || null, usuario, hash, rol || 'cliente']
    );

    const verificationToken = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 24 * 60 * 60 * 1000);
    await db.execute('INSERT INTO Token (userId, token, expires, type) VALUES (?, ?, ?, ?)', [result.insertId, verificationToken, expires, 'verification']);

    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: process.env.EMAIL_PORT,
      secure: false,
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
    });

    const verificationLink = `${process.env.CLIENT_URL}/verificar?token=${verificationToken}`;
    await transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to: correo,
      subject: 'Verifica tu correo - SportLike',
      html: `<p>Hola ${nombre},</p><p>Haz clic en el siguiente enlace para verificar tu correo:</p><a href="${verificationLink}">Verificar correo</a>`
    });

    res.json({ message: 'Usuario registrado correctamente. Revisa tu correo para verificar la cuenta.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error registrando usuario' });
  }
});

app.post('/api/login', async (req, res) => {
  const { usuario, password } = req.body;
  try {
    const db = await getDB();
    const [rows] = await db.execute('SELECT * FROM users WHERE usuario = ?', [usuario]);
    if (rows.length === 0) return res.status(401).json({ error: 'Usuario no encontrado' });
    const user = rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Contraseña incorrecta' });
    if (user.verificado === 0) return res.status(401).json({ error: 'Usuario no verificado' });

    const jwtToken = jwt.sign({ id: user.id, usuario: user.usuario, rol: user.rol, correo: user.correo }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ user: { id: user.id, nombre: user.nombre, usuario: user.usuario, rol: user.rol, correo: user.correo }, token: jwtToken });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error en login' });
  }
});

app.post('/api/forgot-password', async (req, res) => {
  const { correo } = req.body;
  if (!correo) return res.status(400).json({ error: 'Correo requerido' });
  try {
    const db = await getDB();
    const [users] = await db.execute('SELECT id FROM users WHERE correo = ?', [correo]);
    if (users.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });

    const userId = users[0].id;
    const token = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 3600000);
    await db.execute('INSERT INTO Token (userId, token, expires, type) VALUES (?, ?, ?, ?)', [userId, token, expires, 'reset']);

    const resetLink = `${process.env.CLIENT_URL}/recuperar-password?token=${token}`;
    res.json({ message: 'Token generado', resetLink });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error procesando solicitud' });
  }
});

app.post('/api/reset-password', async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) return res.status(400).json({ error: 'Token y contraseña requeridos' });
  if (password.length < 6) return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });
  try {
    const db = await getDB();
    const [rows] = await db.execute('SELECT userId, expires FROM Token WHERE token = ? AND type = "reset"', [token]);
    if (rows.length === 0) return res.status(400).json({ error: 'Token inválido' });

    const tokenData = rows[0];
    if (new Date(tokenData.expires) < new Date()) return res.status(400).json({ error: 'Token expirado' });

    const hash = await bcrypt.hash(password, 10);
    await db.execute('UPDATE users SET password = ? WHERE id = ?', [hash, tokenData.userId]);
    await db.execute('DELETE FROM Token WHERE token = ?', [token]);
    res.json({ message: 'Contraseña restablecida correctamente' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error restableciendo contraseña' });
  }
});

app.post('/api/update-profile', authMiddleware, async (req, res) => {
  const { nombre, apellidoP, apellidoM, telefono, usuario } = req.body;
  if (!nombre || !apellidoP || !usuario) return res.status(400).json({ error: 'Faltan campos requeridos' });
  try {
    const db = await getDB();
    const [exists] = await db.execute('SELECT id FROM users WHERE (usuario = ? OR telefono = ?) AND id != ?', [usuario, telefono || null, req.user.id]);
    if (exists.length > 0) return res.status(400).json({ error: 'Usuario o teléfono ya registrado' });

    await db.execute(
      'UPDATE users SET nombre=?, apellidoP=?, apellidoM=?, telefono=?, usuario=?, updatedAt=NOW() WHERE id=?',
      [nombre, apellidoP, apellidoM || null, telefono || null, usuario, req.user.id]
    );
    res.json({ message: 'Perfil actualizado correctamente' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error actualizando perfil' });
  }
});

app.post('/api/update-password', authMiddleware, async (req, res) => {
  const { actual, nueva } = req.body;
  if (!actual || !nueva) return res.status(400).json({ error: 'Debes enviar ambas contraseñas' });
  try {
    const db = await getDB();
    const [rows] = await db.execute('SELECT password FROM users WHERE id=?', [req.user.id]);
    if (rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });

    const match = await bcrypt.compare(actual, rows[0].password);
    if (!match) return res.status(401).json({ error: 'La contraseña actual es incorrecta' });

    const hash = await bcrypt.hash(nueva, 10);
    await db.execute('UPDATE users SET password=?, updatedAt=NOW() WHERE id=?', [hash, req.user.id]);
    res.json({ message: 'Contraseña actualizada correctamente' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error actualizando contraseña' });
  }
});

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
