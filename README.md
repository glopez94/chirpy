# Chirpy

Chirpy es una aplicación de microblogging donde los usuarios pueden publicar y gestionar chirps (mensajes cortos). La aplicación incluye autenticación, manejo de tokens JWT, y una membresía premium llamada "Chirpy Red".

## Estructura del Proyecto
├── .env 
├── .env.example 
├── .gitignore 
├── assets/ 
│ └── logo.png 
├── chirpy 
├── go.mod 
├── go.sum 
├── index.html 
├── internal/ 
│ ├── auth/ 
│ │ ├── auth_test.go 
│ │ └── auth.go 
│ └── database/ 
│ │ ├── chirps.sql.go 
│ │ ├── db.go 
│ │ ├── models.go 
│ │ ├── refresh_tokens.sql.go 
│ │ └── users.sql.go 
├── main.go 
├── sql/ 
│ ├── queries/ 
│ │ ├── chirps.sql 
│ │ ├── refresh_tokens.sql 
│ │ └── users.sql 
│ └── schema/ 
│ │ ├── 001_users.sql 
│ │ ├── 002_chirps.sql 
│ │ ├── 003_add_hashed_password_to_users.sql 
│ │ ├── 004_create_refresh_tokens.sql 
│ │ └── 005_add_is_chirpy_red_to_users.sql 
└── sqlc.yaml

## Configuración

### Variables de Entorno

Crea un archivo `.env` en la raíz del proyecto con las siguientes variables:

```.sh
DB_URL="postgres://postgres:postgres@localhost:5432/chirpy?sslmode=disable"
PLATFORM="dev"
JWT_SECRET="your_generated_secret"
POLKA_KEY=your_polka_key
```

### Dependencias

Instala las dependencias del proyecto con:

```sh
go mod tidy
```

## Uso

### Levantar el Servidor

Para levantar el servidor, ejecuta:

```sh
go run main.go
```
El servidor estará disponible en http://localhost:8080.

### Endpoints

#### Autenticación

POST /api/users: Crear un nuevo usuario.
POST /api/login: Iniciar sesión y obtener un token JWT.
POST /api/refresh: Obtener un nuevo token JWT usando un token de refresco.
POST /api/revoke: Revocar un token de refresco.

#### Chirps

GET /api/chirps: Obtener todos los chirps. Opcionalmente, se puede filtrar por author_id y ordenar por sort (asc o desc).
POST /api/chirps: Crear un nuevo chirp (requiere autenticación).
GET /api/chirps/{chirpID}: Obtener un chirp por su ID.
DELETE /api/chirps/{chirpID}: Eliminar un chirp por su ID (requiere autenticación y ser el autor).

#### Administración

GET /admin/metrics: Obtener métricas del servidor.
POST /admin/reset: Eliminar todos los usuarios (solo en modo desarrollo).

#### Webhooks

POST /api/polka/webhooks: Manejar webhooks de Polka para actualizar el estado de membresía de los usuarios.

## Pruebas

Para ejecutar las pruebas, usa:

```sh
go test ./...
```

## Contribuciones

Las contribuciones son bienvenidas. Por favor, abre un issue o un pull request para discutir cualquier cambio.

## Licencia

Este proyecto está licenciado bajo la Licencia MIT.