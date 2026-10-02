// ============================================================================
// SERVIDOR EXPRESS.JS - GESTCULTURA
// Ficha SENA: 3013183 | Estudiante: Natalia Mejía Cardona
// ----------------------------------------------------------------------------
// SEGURIDAD APLICADA:
//  - Anti inyección SQL: TODAS las consultas usan parámetros (?), nunca se
//    concatena directamente lo que escribe el usuario.
//  - Contraseñas de usuarios: guardadas cifradas con bcrypt (hash + salt).
//  - Credenciales (BD y API): en el archivo .env, fuera del código y del repositorio.
//  - CORS restringido: solo el frontend de GestCultura puede consumir la API.
//  - Rutas de administrador protegidas por token JWT + rol: solo un admin puede
//    crear, editar o eliminar convocatorias (verificarToken + soloAdmin).
// ============================================================================

const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
require('dotenv').config();

// Llave secreta para firmar los tokens (viene del .env, fuera del código)
const JWT_SECRET = process.env.JWT_SECRET || 'gestcultura_dev_secret_2026';

// Dirección del frontend (para armar el enlace de recuperación de contraseña)
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';

const app = express();
const PORT = 5000;

// ============================================================================
// MIDDLEWARE
// ============================================================================
// Seguridad CORS: solo se permiten peticiones desde el frontend en tu equipo
// (localhost/127.0.0.1, en cualquier puerto de desarrollo de Vite: 5173, 5174, etc.).
// Ninguna otra página web de internet puede consumir esta API desde el navegador.
const corsOptions = {
  origin: (origin, callback) => {
    if (!origin || /^http:\/\/(localhost|127\.0\.0\.1):\d+$/.test(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Origen no permitido por CORS'));
    }
  },
};
app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ============================================================================
// CONFIGURACIÓN DE BASE DE DATOS
// ============================================================================
// Seguridad: las credenciales NO van escritas en el código; se leen del
// archivo .env (que está en .gitignore y no se sube a GitHub).
const connection = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// ============================================================================
// INICIALIZACIÓN DEL SERVIDOR
// ============================================================================
async function initServer() {
  try {
    const conn = await connection.getConnection();
    console.log('✅ Conectado a MySQL: gestion_empatica');
    conn.release();
  } catch (error) {
    console.error('❌ Error conectando a MySQL:', error.message);
    process.exit(1);
  }

  app.listen(PORT, () => {
    console.log(`🚀 Servidor running en http://localhost:${PORT}`);
  });
}

// ============================================================================
// SEGURIDAD - MIDDLEWARES DE TOKEN Y ROL
// ============================================================================

// Verifica que la petición traiga un token válido (persona con sesión iniciada)
function verificarToken(req, res, next) {
  const cabecera = req.headers['authorization'] || '';
  const token = cabecera.startsWith('Bearer ') ? cabecera.slice(7) : null;
  if (!token) {
    return res.status(401).json({ success: false, message: 'Necesitas iniciar sesión para hacer esta acción' });
  }
  try {
    const datos = jwt.verify(token, JWT_SECRET);
    req.usuario = datos; // { idUsuario, idRol }
    next();
  } catch (e) {
    return res.status(401).json({ success: false, message: 'Tu sesión expiró o no es válida. Inicia sesión de nuevo.' });
  }
}

// Verifica que la persona sea administrador (idRol = 1). Úsalo después de verificarToken.
function soloAdmin(req, res, next) {
  if (!req.usuario || Number(req.usuario.idRol) !== 1) {
    return res.status(403).json({ success: false, message: 'Solo un administrador puede realizar esta acción' });
  }
  next();
}

// ============================================================================
// RUTAS - AUTENTICACIÓN
// ============================================================================

// REGISTRO - POST /api/auth/registro ✅ ACTUALIZADO
app.post('/api/auth/registro', async (req, res) => {
  try {
        const { nombre, correo, telefono, fechaNacimiento, cedula, contrasena, confirmContrasena } = req.body;

    if (!nombre || !correo || !telefono || !fechaNacimiento || !contrasena || !confirmContrasena) {
      return res.status(400).json({
        success: false,
        message: 'Todos los campos son requeridos',
      });
    }

    if (contrasena !== confirmContrasena) {
      return res.status(400).json({
        success: false,
        message: 'Las contraseñas no coinciden',
      });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(correo)) {
      return res.status(400).json({
        success: false,
        message: 'Email inválido',
      });
    }

    const salt = await bcrypt.genSalt(10);
    const contrasenaCifrada = await bcrypt.hash(contrasena, salt);

    const conn = await connection.getConnection();
    const [result] = await conn.query(
      'INSERT INTO usuario (nombre, correo, telefono, fechaNacimiento, cedula, contrasena, idRol) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [nombre, correo, telefono, fechaNacimiento, cedula || '', contrasenaCifrada, 2]
    );
    conn.release();

    res.status(201).json({
      success: true,
      message: 'Usuario registrado correctamente',
      idUsuario: result.insertId,
    });
  } catch (error) {
    console.error('Error en registro:', error);
    res.status(500).json({
      success: false,
      message: 'Error al registrar usuario',
    });
  }
});

// LOGIN - POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { correo, contrasena } = req.body;

    if (!correo || !contrasena) {
      return res.status(400).json({
        success: false,
        message: 'Correo y contraseña son requeridos',
      });
    }

    const conn = await connection.getConnection();
    const [usuarios] = await conn.query(
      'SELECT idUsuario, nombre, correo, contrasena, idRol, estado FROM usuario WHERE correo = ?',
      [correo]
    );
    conn.release();

    if (usuarios.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'Usuario o contraseña incorrectos',
      });
    }

    const usuario = usuarios[0];
    const esValida = await bcrypt.compare(contrasena, usuario.contrasena);

    if (!esValida) {
      return res.status(401).json({
        success: false,
        message: 'Usuario o contraseña incorrectos',
      });
    }

    // Si la cuenta fue inactivada por un administrador, no permitimos el acceso.
    if (Number(usuario.estado) === 0) {
      return res.status(403).json({
        success: false,
        message: 'Tu cuenta está inactiva. Comunícate con el administrador.',
      });
    }

    // Generamos el token con la identidad y el rol de la persona (dura 8 horas)
    const token = jwt.sign(
      { idUsuario: usuario.idUsuario, idRol: usuario.idRol },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.json({
      success: true,
      message: 'Sesión iniciada correctamente',
      token,
      user: {
        idUsuario: usuario.idUsuario,
        nombre: usuario.nombre,
        correo: usuario.correo,
        idRol: usuario.idRol,
      },
    });
  } catch (error) {
    console.error('Error en login:', error);
    res.status(500).json({
      success: false,
      message: 'Error al iniciar sesión',
    });
  }
});

// GET obtener datos de un usuario por ID ✅ NUEVO
app.get('/api/usuarios/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const conn = await connection.getConnection();
    const [usuarios] = await conn.query(
      'SELECT idUsuario, nombre, correo, telefono, fechaNacimiento, cedula, idRol FROM usuario WHERE idUsuario = ?',
      [id]
    );
    conn.release();

    if (usuarios.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Usuario no encontrado',
      });
    }

    res.json({
      success: true,
      data: usuarios[0],
    });
  } catch (error) {
    console.error('Error al obtener usuario:', error);
    res.status(500).json({
      success: false,
      message: 'Error al obtener usuario',
    });
  }
});

// ============================================================================
// GESTIÓN DE USUARIOS Y ROLES (solo administradores)
// ----------------------------------------------------------------------------
// Permite al administrador ver todos los usuarios, cambiarles el rol
// (Administrador / Participante) y activarlos o inactivarlos (borrado lógico).
// Nunca se devuelve la contraseña.
// ============================================================================

// GET todos los usuarios (con el nombre de su rol). Solo administradores.
app.get('/api/usuarios', verificarToken, soloAdmin, async (req, res) => {
  try {
    const conn = await connection.getConnection();
    const [usuarios] = await conn.query(
      `SELECT u.idUsuario, u.nombre, u.correo, u.telefono, u.cedula, u.estado, u.idRol, r.nombre AS rol
       FROM usuario u
       JOIN rol r ON u.idRol = r.idRol
       ORDER BY u.idUsuario ASC`
    );
    conn.release();

    res.json({ success: true, data: usuarios });
  } catch (error) {
    console.error('Error al obtener usuarios:', error);
    res.status(500).json({ success: false, message: 'Error al obtener usuarios' });
  }
});

// PUT cambiar el rol de un usuario (1 = Administrador, 2 = Participante). Solo admin.
app.put('/api/usuarios/:id/rol', verificarToken, soloAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { idRol } = req.body;

    if (![1, 2].includes(Number(idRol))) {
      return res.status(400).json({ success: false, message: 'Rol inválido' });
    }
    // Por seguridad, un administrador no puede cambiarse el rol a sí mismo
    // (así evita quedarse sin administradores por error).
    if (Number(req.usuario.idUsuario) === Number(id)) {
      return res.status(400).json({ success: false, message: 'No puedes cambiar tu propio rol' });
    }

    const conn = await connection.getConnection();
    const [result] = await conn.query(
      'UPDATE usuario SET idRol = ? WHERE idUsuario = ?',
      [Number(idRol), id]
    );
    conn.release();

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
    }

    res.json({ success: true, message: 'Rol actualizado correctamente' });
  } catch (error) {
    console.error('Error al cambiar el rol:', error);
    res.status(500).json({ success: false, message: 'Error al cambiar el rol' });
  }
});

// PUT activar (estado=1) o inactivar (estado=0) un usuario - borrado lógico. Solo admin.
app.put('/api/usuarios/:id/estado', verificarToken, soloAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { estado } = req.body;

    if (![0, 1].includes(Number(estado))) {
      return res.status(400).json({ success: false, message: 'Estado inválido' });
    }
    // Un administrador no puede inactivar su propia cuenta.
    if (Number(req.usuario.idUsuario) === Number(id) && Number(estado) === 0) {
      return res.status(400).json({ success: false, message: 'No puedes inactivar tu propia cuenta' });
    }

    const conn = await connection.getConnection();
    const [result] = await conn.query(
      'UPDATE usuario SET estado = ? WHERE idUsuario = ?',
      [Number(estado), id]
    );
    conn.release();

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
    }

    res.json({
      success: true,
      message: Number(estado) === 1 ? 'Usuario activado correctamente' : 'Usuario inactivado correctamente',
    });
  } catch (error) {
    console.error('Error al cambiar el estado del usuario:', error);
    res.status(500).json({ success: false, message: 'Error al cambiar el estado del usuario' });
  }
});

// ============================================================================
// RECUPERACIÓN DE CONTRASEÑA (por correo)
// ----------------------------------------------------------------------------
// Flujo seguro:
//  1) La persona pide recuperar su contraseña con su correo.
//  2) El sistema genera un token temporal (JWT, válido 30 minutos) y envía
//     un enlace al correo registrado.
//  3) La persona abre el enlace y define una contraseña nueva, que se guarda
//     cifrada con bcrypt. El token expira solo a los 30 minutos.
// ============================================================================

// Prepara el "cartero" que envía los correos. Si todavía no hay correo
// configurado en el .env (EMAIL_USER / EMAIL_PASS), devuelve null y el sistema
// funciona en "modo desarrollo" mostrando el enlace en la consola.
function crearTransporter() {
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) return null;
  return nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,          // Puerto 587 con STARTTLS: más compatible con redes y antivirus
    secure: false,      // false en 587 (la conexión se cifra con STARTTLS)
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
    tls: {
      // Tolera certificados de antivirus/proxys locales en desarrollo
      // (algunos antivirus "inspeccionan" el tráfico seguro con su propio certificado).
      rejectUnauthorized: false,
    },
  });
}

// PASO 1 - Solicitar recuperación: POST /api/auth/recuperar
app.post('/api/auth/recuperar', async (req, res) => {
  try {
    const { correo } = req.body;
    if (!correo) {
      return res.status(400).json({ success: false, message: 'El correo es requerido' });
    }

    const conn = await connection.getConnection();
    const [usuarios] = await conn.query(
      'SELECT idUsuario, nombre FROM usuario WHERE correo = ?',
      [correo]
    );
    conn.release();

    // Mensaje genérico: por seguridad no revelamos si el correo existe o no.
    const mensajeGenerico =
      'Si el correo está registrado, te enviaremos un enlace para restablecer tu contraseña. Revisa tu bandeja de entrada (y el correo no deseado).';

    // Si no existe, respondemos igual (sin dar pistas a posibles atacantes).
    if (usuarios.length === 0) {
      return res.json({ success: true, message: mensajeGenerico });
    }

    const usuario = usuarios[0];

    // Token temporal de recuperación (válido 30 minutos)
    const token = jwt.sign(
      { idUsuario: usuario.idUsuario, tipo: 'reset' },
      JWT_SECRET,
      { expiresIn: '30m' }
    );
    const enlace = `${FRONTEND_URL}/restablecer?token=${token}`;

    const transporter = crearTransporter();

    // MODO DESARROLLO: si aún no hay correo configurado, mostramos el enlace
    // en la consola del servidor para poder probar el flujo completo.
    if (!transporter) {
      console.log('🔑 [RECUPERACIÓN - modo desarrollo] Enlace para', correo, '->', enlace);
      return res.json({ success: true, message: mensajeGenerico, enlaceDev: enlace });
    }

    // MODO REAL: enviamos el correo con el enlace.
    await transporter.sendMail({
      from: `"GestCultura" <${process.env.EMAIL_USER}>`,
      to: correo,
      subject: 'Recupera tu contraseña - GestCultura',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto; border:1px solid #eee; border-radius:14px; overflow:hidden">
          <div style="background: linear-gradient(135deg, #7C3AED, #4A148C); color:#fff; padding:24px; text-align:center">
            <h2 style="margin:0">Gestión Empática</h2>
            <p style="margin:6px 0 0; opacity:.9">Recuperación de contraseña</p>
          </div>
          <div style="padding:24px; color:#333; line-height:1.6">
            <p>Hola ${usuario.nombre || ''},</p>
            <p>Recibimos una solicitud para restablecer tu contraseña. Haz clic en el botón para crear una nueva:</p>
            <p style="text-align:center; margin:26px 0">
              <a href="${enlace}" style="background:#7C3AED; color:#fff; text-decoration:none; padding:13px 26px; border-radius:10px; font-weight:bold; display:inline-block">Restablecer mi contraseña</a>
            </p>
            <p style="font-size:13px; color:#777">Este enlace es válido por 30 minutos. Si tú no solicitaste este cambio, puedes ignorar este correo; tu contraseña seguirá igual.</p>
          </div>
        </div>
      `,
    });

    return res.json({ success: true, message: mensajeGenerico });
  } catch (error) {
    console.error('Error en recuperar contraseña:', error);
    res.status(500).json({ success: false, message: 'Error al procesar la solicitud' });
  }
});

// PASO 2 - Definir la nueva contraseña: POST /api/auth/restablecer
app.post('/api/auth/restablecer', async (req, res) => {
  try {
    const { token, contrasena, confirmContrasena } = req.body;

    if (!token || !contrasena || !confirmContrasena) {
      return res.status(400).json({ success: false, message: 'Todos los campos son requeridos' });
    }
    if (contrasena !== confirmContrasena) {
      return res.status(400).json({ success: false, message: 'Las contraseñas no coinciden' });
    }
    if (contrasena.length < 8) {
      return res.status(400).json({ success: false, message: 'La contraseña debe tener al menos 8 caracteres' });
    }

    // Verificamos el token (si expiró o es inválido, no se permite el cambio)
    let datos;
    try {
      datos = jwt.verify(token, JWT_SECRET);
    } catch (e) {
      return res.status(400).json({ success: false, message: 'El enlace expiró o no es válido. Por favor solicita uno nuevo.' });
    }
    if (datos.tipo !== 'reset') {
      return res.status(400).json({ success: false, message: 'El enlace no es válido.' });
    }

    // Guardamos la nueva contraseña cifrada con bcrypt
    const salt = await bcrypt.genSalt(10);
    const contrasenaCifrada = await bcrypt.hash(contrasena, salt);

    const conn = await connection.getConnection();
    const [result] = await conn.query(
      'UPDATE usuario SET contrasena = ? WHERE idUsuario = ?',
      [contrasenaCifrada, datos.idUsuario]
    );
    conn.release();

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
    }

    res.json({ success: true, message: 'Tu contraseña fue actualizada correctamente. Ya puedes iniciar sesión.' });
  } catch (error) {
    console.error('Error al restablecer contraseña:', error);
    res.status(500).json({ success: false, message: 'Error al restablecer la contraseña' });
  }
});

// ============================================================================
// RUTAS - CONVOCATORIAS
// ============================================================================

// GET todas las convocatorias ACTIVAS
app.get('/api/convocatorias', async (req, res) => {
  try {
    const conn = await connection.getConnection();
    const [convocatorias] = await conn.query(
      'SELECT * FROM convocatoria WHERE estado = 1 ORDER BY fechaInicio DESC'
    );
    conn.release();

    res.json({
      success: true,
      data: convocatorias,
    });
  } catch (error) {
    console.error('Error al obtener convocatorias:', error);
    res.status(500).json({
      success: false,
      message: 'Error al obtener convocatorias',
    });
  }
});

// GET TODAS las convocatorias (incluidas las inactivas) - solo administradores
// Se usa en el Panel de Administración para poder ver y reactivar las que
// fueron inactivadas (borrado lógico). El público nunca ve las inactivas.
// IMPORTANTE: esta ruta va ANTES de '/api/convocatorias/:id' para que ':id'
// no confunda la palabra 'admin' con un número de convocatoria.
app.get('/api/convocatorias/admin', verificarToken, soloAdmin, async (req, res) => {
  try {
    const conn = await connection.getConnection();
    const [convocatorias] = await conn.query(
      'SELECT * FROM convocatoria ORDER BY fechaInicio DESC'
    );
    conn.release();

    res.json({
      success: true,
      data: convocatorias,
    });
  } catch (error) {
    console.error('Error al obtener convocatorias (admin):', error);
    res.status(500).json({
      success: false,
      message: 'Error al obtener convocatorias',
    });
  }
});

// GET una convocatoria por ID
app.get('/api/convocatorias/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const conn = await connection.getConnection();
    const [convocatorias] = await conn.query(
      'SELECT * FROM convocatoria WHERE idConvocatoria = ?',
      [id]
    );
    conn.release();

    if (convocatorias.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Convocatoria no encontrada',
      });
    }

    res.json({
      success: true,
      data: convocatorias[0],
    });
  } catch (error) {
    console.error('Error al obtener convocatoria:', error);
    res.status(500).json({
      success: false,
      message: 'Error al obtener convocatoria',
    });
  }
});

// POST crear nueva convocatoria (solo administradores)
app.post('/api/convocatorias', verificarToken, soloAdmin, async (req, res) => {
  try {
    const { nombre, descripcion, fechaInicio, fechaCierre, cupos, idUsuario } = req.body;

    if (!nombre || !fechaInicio || !fechaCierre || !cupos || !idUsuario) {
      return res.status(400).json({
        success: false,
        message: 'Campos requeridos: nombre, fechaInicio, fechaCierre, cupos, idUsuario',
      });
    }

    const conn = await connection.getConnection();
    const [result] = await conn.query(
      'INSERT INTO convocatoria (nombre, descripcion, fechaInicio, fechaCierre, cupos, estado, idUsuario) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [nombre, descripcion || '', fechaInicio, fechaCierre, cupos, 1, idUsuario]
    );
    conn.release();

    res.status(201).json({
      success: true,
      message: 'Convocatoria creada correctamente',
      idConvocatoria: result.insertId,
    });
  } catch (error) {
    console.error('Error al crear convocatoria:', error);
    res.status(500).json({
      success: false,
      message: 'Error al crear convocatoria',
    });
  }
});

// PUT actualizar convocatoria (solo administradores)
app.put('/api/convocatorias/:id', verificarToken, soloAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { nombre, descripcion, fechaInicio, fechaCierre, cupos, estado } = req.body;

    const conn = await connection.getConnection();
    const [result] = await conn.query(
      'UPDATE convocatoria SET nombre = ?, descripcion = ?, fechaInicio = ?, fechaCierre = ?, cupos = ?, estado = ? WHERE idConvocatoria = ?',
      [nombre, descripcion, fechaInicio, fechaCierre, cupos, estado, id]
    );
    conn.release();

    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: 'Convocatoria no encontrada',
      });
    }

    res.json({
      success: true,
      message: 'Convocatoria actualizada correctamente',
    });
  } catch (error) {
    console.error('Error al actualizar convocatoria:', error);
    res.status(500).json({
      success: false,
      message: 'Error al actualizar convocatoria',
    });
  }
});

// DELETE inactivar convocatoria (BORRADO LÓGICO - solo administradores)
// No borra el registro de la base de datos: solo lo marca como inactivo
// (estado = 0). Así la información queda guardada y se puede reactivar luego.
// Las convocatorias inactivas no se muestran al público.
app.delete('/api/convocatorias/:id', verificarToken, soloAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    const conn = await connection.getConnection();
    const [result] = await conn.query(
      'UPDATE convocatoria SET estado = 0 WHERE idConvocatoria = ?',
      [id]
    );
    conn.release();

    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: 'Convocatoria no encontrada',
      });
    }

    res.json({
      success: true,
      message: 'Convocatoria inactivada correctamente',
    });
  } catch (error) {
    console.error('Error al inactivar convocatoria:', error);
    res.status(500).json({
      success: false,
      message: 'Error al inactivar convocatoria',
    });
  }
});

// PUT reactivar convocatoria (BORRADO LÓGICO - solo administradores)
// Vuelve a poner estado = 1 (activa) una convocatoria que estaba inactiva.
app.put('/api/convocatorias/:id/reactivar', verificarToken, soloAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    const conn = await connection.getConnection();
    const [result] = await conn.query(
      'UPDATE convocatoria SET estado = 1 WHERE idConvocatoria = ?',
      [id]
    );
    conn.release();

    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: 'Convocatoria no encontrada',
      });
    }

    res.json({
      success: true,
      message: 'Convocatoria reactivada correctamente',
    });
  } catch (error) {
    console.error('Error al reactivar convocatoria:', error);
    res.status(500).json({
      success: false,
      message: 'Error al reactivar convocatoria',
    });
  }
});

// ============================================================================
// RUTAS - INSCRIPCIONES
// ============================================================================

// GET inscripciones de un usuario
app.get('/api/inscripciones/usuario/:idUsuario', async (req, res) => {
  try {
    const { idUsuario } = req.params;

    const conn = await connection.getConnection();
    const [inscripciones] = await conn.query(
      `SELECT i.*, c.nombre as nombreConvocatoria, c.fechaCierre 
       FROM inscripcion i 
       JOIN convocatoria c ON i.idConvocatoria = c.idConvocatoria 
       WHERE i.idUsuario = ?`,
      [idUsuario]
    );
    conn.release();

    res.json({
      success: true,
      data: inscripciones,
    });
  } catch (error) {
    console.error('Error al obtener inscripciones:', error);
    res.status(500).json({
      success: false,
      message: 'Error al obtener inscripciones',
    });
  }
});

// GET todas las inscripciones
app.get('/api/inscripciones', async (req, res) => {
  try {
    const conn = await connection.getConnection();
    const [inscripciones] = await conn.query(
      `SELECT i.idInscripcion, i.fecha, i.estado, i.motivacion, u.nombre AS postulante, u.correo, u.cedula, c.nombre AS convocatoria
       FROM inscripcion i
       JOIN usuario u ON i.idUsuario = u.idUsuario 
       JOIN convocatoria c ON i.idConvocatoria = c.idConvocatoria 
       ORDER BY i.fecha DESC`
    );
    conn.release();

    res.json({
      success: true,
      data: inscripciones,
    });
  } catch (error) {
    console.error('Error al obtener inscripciones:', error);
    res.status(500).json({
      success: false,
      message: 'Error al obtener inscripciones',
    });
  }
});

// POST crear inscripción
app.post('/api/inscripciones', async (req, res) => {
  try {
    const { idUsuario, idConvocatoria, motivacion } = req.body;

    if (!idUsuario || !idConvocatoria) {
      return res.status(400).json({
        success: false,
        message: 'idUsuario e idConvocatoria son requeridos',
      });
    }

    const conn = await connection.getConnection();

    const [inscripcionesExistentes] = await conn.query(
      'SELECT * FROM inscripcion WHERE idUsuario = ? AND idConvocatoria = ?',
      [idUsuario, idConvocatoria]
    );

    if (inscripcionesExistentes.length > 0) {
      conn.release();
      return res.status(400).json({
        success: false,
        message: 'Ya estás inscrito en esta convocatoria',
      });
    }

    const [result] = await conn.query(
      'INSERT INTO inscripcion (idUsuario, idConvocatoria, motivacion, fecha) VALUES (?, ?, ?, NOW())',
      [idUsuario, idConvocatoria, motivacion || '']
    );
    conn.release();

    res.status(201).json({
      success: true,
      message: 'Inscripción realizada correctamente',
      idInscripcion: result.insertId,
    });
  } catch (error) {
    console.error('Error al crear inscripción:', error);
    res.status(500).json({
      success: false,
      message: 'Error al crear inscripción',
    });
  }
});

// POST postulación completa (Formulario inteligente de 5 pasos)
// Registra en una sola operación (transacción) la inscripción, el formulario
// diligenciado y la firma electrónica, garantizando la integridad de los datos.
app.post('/api/postulaciones', async (req, res) => {
  const { idUsuario, idConvocatoria, motivacion, datos, firmaValor } = req.body;

  if (!idUsuario || !idConvocatoria) {
    return res.status(400).json({ success: false, message: 'idUsuario e idConvocatoria son requeridos' });
  }

  const conn = await connection.getConnection();
  try {
    // ¿Ya está inscrito en esta convocatoria?
    const [existentes] = await conn.query(
      'SELECT idInscripcion FROM inscripcion WHERE idUsuario = ? AND idConvocatoria = ?',
      [idUsuario, idConvocatoria]
    );
    if (existentes.length > 0) {
      conn.release();
      return res.status(400).json({ success: false, message: 'Ya estás inscrito en esta convocatoria' });
    }

    await conn.beginTransaction();

    // 1) Inscripción
    const [rIns] = await conn.query(
      'INSERT INTO inscripcion (idUsuario, idConvocatoria, motivacion, fecha) VALUES (?, ?, ?, NOW())',
      [idUsuario, idConvocatoria, motivacion || '']
    );
    const idInscripcion = rIns.insertId;

    // 2) Formulario diligenciado (los datos se guardan como JSON de texto)
    const [rForm] = await conn.query(
      'INSERT INTO formulario (datos, fechaDiligenciamiento, idInscripcion) VALUES (?, CURDATE(), ?)',
      [JSON.stringify(datos || {}), idInscripcion]
    );
    const idFormulario = rForm.insertId;

    // 3) Firma electrónica (constancia de texto; la imagen de la firma va en el PDF)
    await conn.query(
      'INSERT INTO firma_electronica (valor, fecha, idFormulario) VALUES (?, CURDATE(), ?)',
      [String(firmaValor || 'Firmado digitalmente').slice(0, 255), idFormulario]
    );

    await conn.commit();
    conn.release();

    res.status(201).json({
      success: true,
      message: 'Postulación registrada correctamente',
      idInscripcion,
      idFormulario,
    });
  } catch (error) {
    try { await conn.rollback(); } catch (e) { /* noop */ }
    conn.release();
    console.error('Error al registrar la postulación:', error);
    res.status(500).json({ success: false, message: 'Error al registrar la postulación' });
  }
});

// ============================================================================
// RUTA - ASISTENTE MONET (IA con Gemini)
// ============================================================================
app.post('/api/monet', async (req, res) => {
  try {
    const { mensaje } = req.body;
    if (!mensaje) {
      return res.status(400).json({ success: false, message: 'Falta el mensaje' });
    }

    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      return res.status(500).json({ success: false, message: 'Falta la API key de Gemini' });
    }

    const instruccion =
      'Eres Monet, un perrito asistente empático y cálido del portal cultural GestCultura. ' +
      'Monet es de género masculino: refiérete SIEMPRE a ti mismo en masculino (un perrito, tu perrito compañero, ' +
      'estoy listo, aquí estoy para acompañarte). Nunca uses "perrita" ni te describas en femenino. ' +
      'Ayudas a las personas (incluidos adultos mayores) a postularse a convocatorias de becas y ' +
      'estímulos culturales. Responde SIEMPRE en español, de forma breve (máximo 3 frases), amable y ' +
      'sin tecnicismos. Si preguntan cómo inscribirse, diles que entren a Convocatorias, elijan una y ' +
      'den clic en "Inscribirme / Postularse", iniciando sesión primero.';

    const url =
      'https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent?key=' +
      apiKey;

    const respuesta = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        systemInstruction: { parts: [{ text: instruccion }] },
        contents: [{ role: 'user', parts: [{ text: mensaje }] }],
      }),
    });

    const datos = await respuesta.json();

    if (!respuesta.ok) {
      console.error('Error de Gemini:', JSON.stringify(datos));
      return res.status(500).json({ success: false, message: 'Error al consultar la IA' });
    }

    const texto =
      (datos &&
        datos.candidates &&
        datos.candidates[0] &&
        datos.candidates[0].content &&
        datos.candidates[0].content.parts &&
        datos.candidates[0].content.parts[0] &&
        datos.candidates[0].content.parts[0].text) ||
      'Disculpa, no pude generar una respuesta en este momento.';

    res.json({ success: true, respuesta: texto });
  } catch (error) {
    console.error('Error en /api/monet:', error);
    res.status(500).json({ success: false, message: 'Error en el asistente Monet' });
  }
});

// ============================================================================
// MANEJO DE ERRORES - RUTA 404
// ============================================================================
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Ruta no encontrada',
  });
});

// ============================================================================
// INICIAR SERVIDOR
// ============================================================================
initServer();

module.exports = app;