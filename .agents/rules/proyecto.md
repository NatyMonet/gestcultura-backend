# Reglas del Proyecto GestCultura

## Stack Obligatorio
- Backend: Node.js (v18+) + Express.js 4.18+
- Base de datos: MySQL 8.0 (esquema: gestion_empatica)
- Frontend: React 19 + TypeScript + Vite + Tailwind CSS
- Validación: bcrypt para contraseñas, input validation en servidor

## Requisitos Técnicos

### Seguridad
- NUNCA usar concatenación SQL. Usar SIEMPRE prepared statements (?)
- Variables sensibles en .env (nunca en código)
- Contraseñas hasheadas con bcrypt (rounds >= 10)
- CORS configurado correctamente

### Base de datos
- Queries parametrizadas: db.query('SELECT * FROM usuarios WHERE id = ?', [id])
- Validar datos que llegan del formulario ANTES de guardar
- Comentarios en SQL explicando la lógica

### Frontend
- SweetAlert2 para validaciones y mensajes de éxito/error
- Manejo de errores con try-catch
- No guardar credenciales en localStorage
- Fetch a endpoints REST (no mockData)

### Código
- CamelCase para variables/funciones
- Comentarios en español explicando lógica compleja
- Estructura clara: router -> controller -> service -> db

## Prohibiciones
- NO SQL injection (NO concatenación)
- NO Contraseñas en texto plano
- NO console.log() en producción (usar logger)
- NO Dependencias no autorizadas sin consultar

## Modo Always On
Este archivo debe estar SIEMPRE activo durante sesiones agénticas.