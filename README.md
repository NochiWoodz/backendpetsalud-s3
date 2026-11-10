# Backend Clínica PetSalud — Spring Security + JWT (Desarrollo Backend II, S3: seguridad integrada)

Backend Spring Boot 3.3.6 / Java 17 con autenticación **stateless mediante JWT** (JJWT 0.12.6),
contraseñas con **BCrypt** y autorización por rol: **CLIENTE, EMPLEADO, GERENTE**.

## Ejecutar
```
mvn spring-boot:run          # H2 en archivo (./data/petsalud-s3), no requiere instalar nada
mvn test                     # JwtUtil, login/filtro JWT/roles y amenazas (SQLi, XSS, CSRF)
```
Si ya ejecutó la versión de la Semana 1 en la misma carpeta, no hay conflicto: esta versión usa otro archivo de base de datos.

Usuarios de demostración (se crean con la BD vacía; clave `Petsalud2025`):
`gerente@petsalud.cl`, `empleado@petsalud.cl`, `cliente@petsalud.cl`.

## Uso de la API
```
POST /api/auth/login      {"email":"cliente@petsalud.cl","password":"Petsalud2025"}   -> {"token":"...","tipo":"Bearer",...}
GET  /api/productos       Authorization: Bearer <token>
POST /api/auth/registro   (público; crea siempre un CLIENTE)
GET  /api/auth/perfil     Authorization: Bearer <token>
POST /api/gerencia/usuarios   (solo GERENTE; crea EMPLEADO o GERENTE)
```

## Componentes de seguridad
- `security/SecurityConfig`: deshabilita login por defecto, HTTP Basic, logout y CSRF; sesión STATELESS; reglas por URL y rol; filtro JWT antes de `UsernamePasswordAuthenticationFilter`.
- `security/JwtUtil`: genera y valida tokens HS256 (claims sub, uid, roles, iss, iat, exp, jti).
- `security/JwtAuthenticationFilter`: valida el `Authorization: Bearer` en cada petición.
- `security/UsuarioDetailsService` / `UsuarioDetails`: carga el usuario desde la base de datos.
- `controller/AuthController`: registro, login y perfil.
- `security/AccesoService` + `@PreAuthorize`: cada cliente solo accede a sus propios datos.
- `security/IntentosLoginService` + `AuditoriaSeguridadListener`: bloqueo tras 5 fallos y log de auditoría.

- `config/SanitizacionEntrada`: rechaza (400) HTML/script en cualquier texto JSON recibido (defensa en profundidad contra XSS almacenado).
- `config/ManejadorErrores`: errores uniformes sin detalles internos; registra en auditoría las entradas rechazadas.

## Pruebas de amenazas (`AmenazasSeguridadTest`)
| Amenaza | Qué se prueba |
|---|---|
| Inyección SQL | login con `' OR '1'='1`, parámetro de consulta, id de ruta, texto con `DROP TABLE` guardado como texto |
| XSS | `<script>`, `<img onerror>`, `javascript:` en registro y productos; texto legítimo aceptado; cabeceras CSP / nosniff / X-Frame-Options |
| CSRF | POST desde otro origen sin token, cookie de sesión sin efecto, el login no crea cookies |
| Fuga de información | mismo mensaje para usuario existente e inexistente |

## Estructura
`controller` (API REST) · `service` / `repository` / `entity` (dominio) · `dto` (entradas validadas) · `security` (JWT, filtro, roles, auditoría) · `config` (errores, sanitización, datos de demostración) · `postman` (colección de 24 solicitudes).

## Configuración
La clave JWT se define en `petsalud.jwt.secret` (Base64, mínimo 256 bits). El valor por defecto es solo para
desarrollo; en producción use la variable de entorno `JWT_SECRET` (perfil `mysql`, que no tiene valor por defecto).
Generar una clave: `openssl rand -base64 32`.

## Postman
Importar `postman/PetSalud_JWT.postman_collection.json` y ejecutar con *Run collection* sobre una BD
recién creada (detener la app, borrar la carpeta `data/` y reiniciar).
