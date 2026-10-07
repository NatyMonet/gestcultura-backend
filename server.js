/**
 * Nombre del archivo: server.js
 * Descripción: Servidor principal (Node.js + Express). Define las rutas de la API,
 *              la conexión a MySQL y la seguridad (JWT, CORS).
 * Autor: Natalia Mejía Cardona
 * Fecha de creación: 2026-09-05
 * Última modificación: 2026-10-07
 * Licencia: Uso académico — Corporación Cinefilia / SENA.
 */
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
const crypto = require('crypto');
require('dotenv').config();

// Llave secreta para firmar los tokens (viene del .env, fuera del código)
const JWT_SECRET = process.env.JWT_SECRET || 'gestcultura_dev_secret_2026';

// Dirección del frontend (para armar el enlace de recuperación de contraseña)
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';

// Valor de la inscripción (en COP). Lo decide SIEMPRE el servidor, nunca el
// navegador: el precio jamás viaja desde el cliente (principio de seguridad
// que recalca el material del instructor sobre pasarelas de pago).
const VALOR_INSCRIPCION = 50000;

// API de Wompi en modo pruebas (sandbox). Las llaves viven en el .env.
const WOMPI_API = process.env.WOMPI_API || 'https://sandbox.wompi.co/v1';

const app = express();
const PORT = process.env.PORT || 5000;

// ============================================================================
// MIDDLEWARE
// ============================================================================
// Seguridad CORS: solo se permiten peticiones desde el frontend en tu equipo
// (localhost/127.0.0.1, en cualquier puerto de desarrollo de Vite: 5173, 5174, etc.).
// Ninguna otra página web de internet puede consumir esta API desde el navegador.
// Orígenes permitidos en producción (la URL del frontend publicado).
// Se leen de FRONTEND_URL (puede traer varias separadas por coma).
const ORIGENES_PERMITIDOS = (process.env.FRONTEND_URL || 'http://localhost:5173')
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);

const corsOptions = {
  origin: (origin, callback) => {
    if (
      !origin ||
      /^http:\/\/(localhost|127\.0\.0\.1):\d+$/.test(origin) ||
      ORIGENES_PERMITIDOS.includes(origin)
    ) {
      callback(null, true);
    } else {
      callback(new Error('Origen no permitido por CORS'));
    }
  },
};
app.use(cors(corsOptions));
// Límite ampliado para permitir el envío de documentos (PDF) en base64.
app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true, limit: '15mb' }));

// ============================================================================
// CONFIGURACIÓN DE BASE DE DATOS
// ============================================================================
// Seguridad: las credenciales NO van escritas en el código; se leen del
// archivo .env (que está en .gitignore y no se sube a GitHub).
const connection = mysql.createPool({
  host: process.env.DB_HOST,
  // Puerto: en local MySQL usa 3306; en la nube (Aiven) usa el que indique DB_PORT.
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  // SSL: proveedores en la nube como Aiven exigen conexión cifrada.
  // Se activa con DB_SSL=true (producción). En local queda sin SSL.
  ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : undefined,
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
      `SELECT u.idUsuario, u.nombre, u.correo, u.telefono, u.cedula, u.fechaNacimiento, u.estado, u.idRol, r.nombre AS rol
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
// FORMULARIO DE CONTACTO (envía el mensaje al correo de la organización)
// ----------------------------------------------------------------------------
// La persona escribe nombre, correo, asunto y mensaje desde la página pública
// de Contacto. El sistema envía ese mensaje al correo de Cinefilia usando el
// mismo "cartero" (nodemailer) de la recuperación de contraseña. El "responder
// a" (replyTo) queda con el correo de la persona, para que Cinefilia pueda
// contestarle directamente con un solo clic.
// ============================================================================
app.post('/api/contacto', async (req, res) => {
  try {
    const { nombre, correo, asunto, mensaje } = req.body;

    // Validaciones básicas (que no lleguen campos vacíos)
    if (!nombre || !correo || !mensaje) {
      return res.status(400).json({ success: false, message: 'Por favor completa tu nombre, correo y mensaje.' });
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(correo)) {
      return res.status(400).json({ success: false, message: 'Por favor escribe un correo electrónico válido.' });
    }

    // Correo de la organización donde se reciben los mensajes
    const correoDestino = process.env.EMAIL_CONTACTO || 'info@cinefilia.org.co';
    const asuntoFinal = asunto && asunto.trim() ? asunto.trim() : 'Nuevo mensaje de contacto';

    const transporter = crearTransporter();

    // MODO DESARROLLO: si aún no hay correo configurado, mostramos el mensaje
    // en la consola del servidor para poder probar el flujo completo.
    if (!transporter) {
      console.log('📨 [CONTACTO - modo desarrollo] De:', nombre, `<${correo}>`, '| Asunto:', asuntoFinal, '| Mensaje:', mensaje);
      return res.json({ success: true, message: 'Recibimos tu mensaje. ¡Gracias por escribirnos! (modo desarrollo)' });
    }

    // MODO REAL: enviamos el mensaje al correo de la organización.
    await transporter.sendMail({
      from: `"GestCultura - Contacto" <${process.env.EMAIL_USER}>`,
      to: correoDestino,
      replyTo: `"${nombre}" <${correo}>`,
      subject: `[Contacto web] ${asuntoFinal}`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 520px; margin: 0 auto; border:1px solid #eee; border-radius:14px; overflow:hidden">
          <div style="background: linear-gradient(135deg, #7C3AED, #4A148C); color:#fff; padding:24px; text-align:center">
            <h2 style="margin:0">Gestión Empática</h2>
            <p style="margin:6px 0 0; opacity:.9">Nuevo mensaje desde el formulario de contacto</p>
          </div>
          <div style="padding:24px; color:#333; line-height:1.6">
            <p><strong>Nombre:</strong> ${nombre}</p>
            <p><strong>Correo:</strong> ${correo}</p>
            <p><strong>Asunto:</strong> ${asuntoFinal}</p>
            <hr style="border:none; border-top:1px solid #eee; margin:16px 0" />
            <p style="white-space:pre-line">${mensaje}</p>
            <hr style="border:none; border-top:1px solid #eee; margin:16px 0" />
            <p style="font-size:13px; color:#777">Puedes responder directamente a este correo para contestarle a la persona.</p>
          </div>
        </div>
      `,
    });

    return res.json({ success: true, message: '¡Gracias por escribirnos! Recibimos tu mensaje y te responderemos pronto.' });
  } catch (error) {
    console.error('Error en formulario de contacto:', error);
    res.status(500).json({ success: false, message: 'No pudimos enviar tu mensaje. Intenta de nuevo en un momento.' });
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
      `SELECT i.*, c.nombre as nombreConvocatoria, c.fechaCierre,
              (SELECT COUNT(*) FROM comprobante cp WHERE cp.idInscripcion = i.idInscripcion) AS tienePago
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
      `SELECT i.idInscripcion, i.fecha, i.estado, i.motivacion, u.nombre AS postulante, u.correo, u.cedula, u.fechaNacimiento, c.nombre AS convocatoria,
              (SELECT f.datos FROM formulario f WHERE f.idInscripcion = i.idInscripcion ORDER BY f.idFormulario DESC LIMIT 1) AS datos
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
// RUTA - SUBIR DOCUMENTO (los archivos se guardan en el Google Drive de
// Cinefilia a través de un "puente" en Google Apps Script).
// ----------------------------------------------------------------------------
// El navegador envía el archivo en base64; este servidor lo reenvía (servidor
// a servidor, sin CORS) al Apps Script, que lo guarda en una carpeta del Drive
// organizada por convocatoria y postulante, y devuelve el enlace del archivo.
// La URL y la clave del puente viven en el .env (APPS_SCRIPT_URL, UPLOAD_SECRET).
// ============================================================================
app.post('/api/subir-documento', async (req, res) => {
  try {
    const { dataBase64, filename, mimeType, convocatoria, postulante } = req.body;

    if (!dataBase64 || !filename) {
      return res.status(400).json({ ok: false, message: 'Falta el archivo o el nombre' });
    }
    if (!process.env.APPS_SCRIPT_URL || !process.env.UPLOAD_SECRET) {
      return res.status(500).json({ ok: false, message: 'El almacenamiento de documentos no está configurado' });
    }

    // Límite de tamaño: ~10 MB de archivo (el base64 pesa ~33% más).
    const tamanoAprox = Math.floor((String(dataBase64).length * 3) / 4);
    if (tamanoAprox > 10 * 1024 * 1024) {
      return res.status(413).json({ ok: false, message: 'El archivo supera el límite de 10 MB' });
    }

    const respuesta = await fetch(process.env.APPS_SCRIPT_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        secret: process.env.UPLOAD_SECRET,
        dataBase64,
        filename,
        mimeType: mimeType || 'application/octet-stream',
        convocatoria: convocatoria || 'Sin convocatoria',
        postulante: postulante || 'Sin nombre',
      }),
      redirect: 'follow',
    });

    const data = await respuesta.json();
    if (!data || !data.ok) {
      return res.status(502).json({ ok: false, message: (data && data.error) || 'No se pudo guardar el documento en Drive' });
    }

    res.json({ ok: true, url: data.url, id: data.id, nombre: data.nombre });
  } catch (error) {
    console.error('Error al subir el documento:', error);
    res.status(500).json({ ok: false, message: 'Error al subir el documento' });
  }
});

// ============================================================================
// RUTAS - PAGOS (Pasarelas de pago - Módulo 5)
// ----------------------------------------------------------------------------
//  - WOMPI: integración REAL en modo pruebas (sandbox). El servidor calcula el
//    monto y la FIRMA DE INTEGRIDAD (SHA-256), y el resultado se confirma
//    consultando la transacción DIRECTAMENTE a Wompi (servidor a servidor),
//    nunca creyéndole a la URL que ve el navegador.
//  - PayU y PayPal: simulación para el PMV (la interfaz queda lista para
//    integrarlas igual que Wompi más adelante).
//
// PRINCIPIO DE SEGURIDAD: el valor a pagar lo decide SIEMPRE el servidor
// (VALOR_INSCRIPCION). Nunca se confía en el monto que envía el navegador.
// ============================================================================

// Firma de integridad que exige Wompi:
// SHA-256 de  referencia + monto_en_centavos + moneda + secreto_de_integridad
function firmaIntegridadWompi(referencia, centavos, moneda = 'COP') {
  const cadena = `${referencia}${centavos}${moneda}${process.env.WOMPI_INTEGRITY_SECRET}`;
  return crypto.createHash('sha256').update(cadena).digest('hex');
}

// --- PayU / PayPal: pago simulado para el PMV -------------------------------
app.post('/api/pagos', async (req, res) => {
  const { idInscripcion, pasarela } = req.body;

  if (!idInscripcion) {
    return res.status(400).json({ success: false, message: 'idInscripcion es requerido' });
  }

  // El monto lo decide el SERVIDOR; se ignora cualquier valor enviado por el navegador.
  const monto = VALOR_INSCRIPCION;

  const conn = await connection.getConnection();
  try {
    // ¿Ya existe un pago registrado para esta inscripción?
    const [existentes] = await conn.query(
      'SELECT idComprobante FROM comprobante WHERE idInscripcion = ?',
      [idInscripcion]
    );
    if (existentes.length > 0) {
      conn.release();
      return res.status(400).json({ success: false, message: 'Esta inscripción ya tiene un pago registrado' });
    }

    const canal = `Web - ${String(pasarela || 'Pasarela').slice(0, 22)}`;
    await conn.query(
      "INSERT INTO comprobante (archivo, monto, fechaCarga, estado, canalEnvio, idInscripcion) VALUES (?, ?, CURDATE(), 'Validado', ?, ?)",
      [`pago_simulado_${(pasarela || 'web').toLowerCase()}.txt`, monto, canal, idInscripcion]
    );
    conn.release();

    res.status(201).json({ success: true, message: 'Pago registrado correctamente (simulación)', monto });
  } catch (error) {
    conn.release();
    console.error('Error al registrar el pago:', error);
    res.status(500).json({ success: false, message: 'Error al registrar el pago' });
  }
});

// --- WOMPI · 1) Iniciar el pago (modo pruebas / sandbox) --------------------
// El servidor fija el monto, genera la referencia y calcula la firma de
// integridad, y entrega al navegador solo los datos públicos para abrir el
// checkout de Wompi. La llave privada y el secreto de integridad NUNCA salen
// del servidor.
app.post('/api/pagos/wompi/iniciar', async (req, res) => {
  const { idInscripcion } = req.body;

  if (!idInscripcion) {
    return res.status(400).json({ success: false, message: 'idInscripcion es requerido' });
  }
  if (!process.env.WOMPI_PUBLIC_KEY || !process.env.WOMPI_INTEGRITY_SECRET) {
    // Si todavía no se han configurado las llaves de prueba de Wompi, no mostramos
    // un error técnico: avisamos amablemente que está en configuración y que se
    // puede usar otra pasarela mientras tanto.
    return res.status(200).json({
      success: false,
      configPendiente: true,
      message: 'El pago con Wompi (modo pruebas / sandbox) está en configuración. Por ahora puedes usar PayU o PayPal.',
    });
  }

  const conn = await connection.getConnection();
  try {
    // La inscripción debe existir.
    const [ins] = await conn.query('SELECT idInscripcion FROM inscripcion WHERE idInscripcion = ?', [idInscripcion]);
    if (ins.length === 0) {
      conn.release();
      return res.status(404).json({ success: false, message: 'Inscripción no encontrada' });
    }
    // ¿Ya tiene un pago registrado?
    const [existentes] = await conn.query('SELECT idComprobante FROM comprobante WHERE idInscripcion = ?', [idInscripcion]);
    if (existentes.length > 0) {
      conn.release();
      return res.status(400).json({ success: false, message: 'Esta inscripción ya tiene un pago registrado' });
    }
    conn.release();

    // El monto lo fija el SERVIDOR (en centavos, como lo pide Wompi).
    const centavos = VALOR_INSCRIPCION * 100;
    // Referencia única que lleva el id de la inscripción para reconocerla al volver.
    const referencia = `CINE-${idInscripcion}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    const firma = firmaIntegridadWompi(referencia, centavos, 'COP');
    const redirectUrl = `${FRONTEND_URL}/pago-resultado`;

    res.json({
      success: true,
      publicKey: process.env.WOMPI_PUBLIC_KEY,
      referencia,
      amountInCents: centavos,
      moneda: 'COP',
      firma,
      redirectUrl,
      montoCop: VALOR_INSCRIPCION,
    });
  } catch (error) {
    try { conn.release(); } catch (e) { /* noop */ }
    console.error('Error al iniciar el pago con Wompi:', error);
    res.status(500).json({ success: false, message: 'Error al iniciar el pago con Wompi' });
  }
});

// --- WOMPI · 2) Confirmar el resultado (servidor a servidor) ----------------
// Cuando Wompi devuelve al cliente con ?id=TRANSACCION, el servidor le pregunta
// DIRECTAMENTE a Wompi el estado real (no se confía en la URL del navegador).
// Si quedó APROBADA y el monto coincide con lo que fijó el servidor, registra
// el comprobante (una sola vez).
app.get('/api/pagos/wompi/resultado', async (req, res) => {
  const { id } = req.query;
  if (!id) {
    return res.status(400).json({ success: false, message: 'Falta el id de la transacción' });
  }

  try {
    const resp = await fetch(`${WOMPI_API}/transactions/${encodeURIComponent(id)}`);
    const json = await resp.json();
    const tx = json && json.data ? json.data : null;
    if (!tx) {
      return res.status(404).json({ success: false, message: 'No se encontró la transacción en Wompi' });
    }

    const estadoWompi = tx.status; // APPROVED | DECLINED | VOIDED | ERROR | PENDING
    const referencia = tx.reference || '';
    const centavos = Number(tx.amount_in_cents) || 0;

    // La referencia tiene la forma CINE-<idInscripcion>-XXXX
    const partes = referencia.split('-');
    const idInscripcion = partes.length >= 2 ? Number(partes[1]) : null;

    const mapa = { APPROVED: 'APROBADA', DECLINED: 'RECHAZADA', VOIDED: 'RECHAZADA', ERROR: 'ERROR', PENDING: 'PENDIENTE' };
    let estado = mapa[estadoWompi] || 'ERROR';

    // Validación de monto: debe coincidir con lo que fijó el servidor.
    const esperado = VALOR_INSCRIPCION * 100;
    if (estado === 'APROBADA' && centavos !== esperado) {
      estado = 'ERROR';
    }

    // Si quedó aprobada y hay inscripción, registramos el comprobante (solo una vez).
    if (estado === 'APROBADA' && idInscripcion) {
      const conn = await connection.getConnection();
      try {
        const [existentes] = await conn.query('SELECT idComprobante FROM comprobante WHERE idInscripcion = ?', [idInscripcion]);
        if (existentes.length === 0) {
          await conn.query(
            "INSERT INTO comprobante (archivo, monto, fechaCarga, estado, canalEnvio, idInscripcion) VALUES (?, ?, CURDATE(), 'Validado', 'Web - Wompi', ?)",
            [`wompi_${tx.id}.txt`, centavos / 100, idInscripcion]
          );
        }
      } finally {
        conn.release();
      }
    }

    res.json({
      success: true,
      estado,
      estadoWompi,
      referencia,
      idInscripcion,
      monto: centavos / 100,
      transaccionId: tx.id,
    });
  } catch (error) {
    console.error('Error al consultar la transacción de Wompi:', error);
    res.status(500).json({ success: false, message: 'Error al confirmar el pago con Wompi' });
  }
});

// --- Comprobante de PAGO (recibo estilo pasarela) ---------------------------
// Devuelve los datos del pago de una inscripción para mostrar/descargar el
// recibo (distinto al comprobante de radicación de la postulación). El ID de
// transacción y la referencia se derivan de forma estable del comprobante, para
// que siempre salgan iguales al reabrir el recibo.
app.get('/api/pagos/comprobante/:idInscripcion', async (req, res) => {
  const { idInscripcion } = req.params;
  const conn = await connection.getConnection();
  try {
    const [rows] = await conn.query(
      `SELECT cp.idComprobante, cp.monto, cp.fechaCarga, cp.estado, cp.canalEnvio,
              u.nombre AS postulante, u.correo,
              c.nombre AS convocatoria
       FROM comprobante cp
       JOIN inscripcion i ON cp.idInscripcion = i.idInscripcion
       JOIN usuario u ON i.idUsuario = u.idUsuario
       JOIN convocatoria c ON i.idConvocatoria = c.idConvocatoria
       WHERE cp.idInscripcion = ?
       ORDER BY cp.idComprobante DESC
       LIMIT 1`,
      [idInscripcion]
    );
    conn.release();

    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Esta inscripción no tiene un pago registrado' });
    }

    const cp = rows[0];
    // Medio de pago legible: "Web - PayU" -> "PayU"
    const medioPago = String(cp.canalEnvio || '').replace(/^Web\s*-\s*/i, '').trim() || 'En línea';
    // Referencia e ID de transacción estables (derivados del comprobante)
    const base = crypto.createHash('sha256').update(`${cp.idComprobante}-${idInscripcion}`).digest('hex');
    const referencia = `CINE-${idInscripcion}-${base.slice(0, 6).toUpperCase()}`;
    const transaccionId = `${base.slice(0, 8)}-${base.slice(8, 12)}-${base.slice(12, 16)}-${base.slice(16, 24)}`;

    res.json({
      success: true,
      data: {
        transaccionId,
        estado: cp.estado === 'Validado' ? 'APROBADO' : String(cp.estado || '').toUpperCase(),
        descripcion: `Pago de inscripción · ${cp.convocatoria}`,
        referencia,
        valor: Number(cp.monto),
        moneda: 'COP',
        fecha: cp.fechaCarga,
        medioPago,
        correo: cp.correo,
        postulante: cp.postulante,
        convocatoria: cp.convocatoria,
      },
    });
  } catch (error) {
    try { conn.release(); } catch (e) { /* noop */ }
    console.error('Error al obtener el comprobante de pago:', error);
    res.status(500).json({ success: false, message: 'Error al obtener el comprobante de pago' });
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
