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
//  - PENDIENTE (próximo paso): rutas protegidas por rol (login/admin con token JWT).
// ============================================================================

const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
const PORT = 5000;

// ============================================================================
// MIDDLEWARE
// ============================================================================
// Seguridad CORS: solo se permiten peticiones desde el frontend de GestCultura
// (así ninguna otra página web puede consumir esta API desde el navegador).
const corsOptions = {
  origin: ['http://localhost:5173', 'http://127.0.0.1:5173'],
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
      'SELECT idUsuario, nombre, correo, contrasena, idRol FROM usuario WHERE correo = ?',
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

    res.json({
      success: true,
      message: 'Sesión iniciada correctamente',
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

// POST crear nueva convocatoria
app.post('/api/convocatorias', async (req, res) => {
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

// PUT actualizar convocatoria
app.put('/api/convocatorias/:id', async (req, res) => {
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

// DELETE eliminar convocatoria
app.delete('/api/convocatorias/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const conn = await connection.getConnection();
    const [result] = await conn.query(
      'DELETE FROM convocatoria WHERE idConvocatoria = ?',
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
      message: 'Convocatoria eliminada correctamente',
    });
  } catch (error) {
    console.error('Error al eliminar convocatoria:', error);
    res.status(500).json({
      success: false,
      message: 'Error al eliminar convocatoria',
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
      `SELECT i.idInscripcion, i.fecha, i.motivacion, u.nombre AS postulante, u.correo, u.cedula, c.nombre AS convocatoria 
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