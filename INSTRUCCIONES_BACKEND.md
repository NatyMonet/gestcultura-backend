# 🚀 GESTCULTURA - Backend Setup

## 📋 Archivos incluidos:
- `server.js` — Servidor Express con todas las rutas
- `package.json` — Dependencias del proyecto

---

## 🔧 INSTALACIÓN

### Paso 1: Instalar Node.js (si no lo tienes)
Descarga desde: https://nodejs.org/

### Paso 2: Instalar dependencias
```bash
npm install
```

### Paso 3: Ejecutar el servidor
```bash
npm start
```

✅ Verás:
```
🚀 Servidor running en http://localhost:5000
✅ Conectado a MySQL: gestion_empatica
```

---

## 📡 ENDPOINTS DISPONIBLES

### 1️⃣ REGISTRO DE USUARIO
**POST** `http://localhost:5000/api/auth/registro`

**Body (JSON):**
```json
{
  "nombre": "Ana García",
  "correo": "ana@ejemplo.com",
  "telefono": "+57 300 123 4567",
  "contrasena": "Password123!",
  "confirmContrasena": "Password123!"
}
```

**Respuesta exitosa (200):**
```json
{
  "success": true,
  "message": "Cuenta creada exitosamente"
}
```

---

### 2️⃣ LOGIN
**POST** `http://localhost:5000/api/auth/login`

**Body (JSON):**
```json
{
  "correo": "ana@ejemplo.com",
  "contrasena": "Password123!"
}
```

**Respuesta exitosa (200):**
```json
{
  "success": true,
  "message": "Sesión iniciada correctamente",
  "user": {
    "idUsuario": 1,
    "nombre": "Ana García",
    "correo": "ana@ejemplo.com",
    "idRol": 2
  }
}
```

---

### 3️⃣ OBTENER CONVOCATORIAS
**GET** `http://localhost:5000/api/convocatorias`

**Respuesta (200):**
```json
{
  "success": true,
  "data": [
    {
      "idConvocatoria": 1,
      "nombre": "Convocatoria 2026",
      "descripcion": "...",
      "fechaInicio": "2026-09-01",
      "fechaCierre": "2026-10-30",
      "cupos": 50
    }
  ]
}
```

---

### 4️⃣ CREAR INSCRIPCIÓN
**POST** `http://localhost:5000/api/inscripciones`

**Body (JSON):**
```json
{
  "idUsuario": 1,
  "idConvocatoria": 1,
  "datos": {
    "edad": 45,
    "disciplina": "Cine"
  }
}
```

**Respuesta (200):**
```json
{
  "success": true,
  "message": "Inscripción creada correctamente",
  "idInscripcion": 5
}
```

---

## 🔌 CONECTAR CON FRONTEND

En tu código React/JavaScript, usa `fetch` o `axios`:

```javascript
// Ejemplo con fetch
const registrar = async () => {
  const response = await fetch('http://localhost:5000/api/auth/registro', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      nombre: "Ana García",
      correo: "ana@ejemplo.com",
      telefono: "+57 300 123 4567",
      contrasena: "Password123!",
      confirmContrasena: "Password123!"
    })
  });
  
  const data = await response.json();
  console.log(data);
};
```

---

## ⚠️ IMPORTANTE

- MySQL debe estar **corriendo** en tu PC
- La BD `gestion_empatica` debe estar **creada**
- El servidor corre en **puerto 5000** (puedes cambiar `PORT` en el código)

---

## 🐛 Si hay errores:

1. **"Cannot find module"** → Ejecuta `npm install`
2. **"Connection refused"** → Verifica que MySQL esté corriendo
3. **"Unknown database"** → Ejecuta el script SQL: `base_datos_gestion_empatica.sql`

---

**¿Necesitas ayuda?** Contacta al equipo. 🚀
