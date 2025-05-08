# Demo de autenticación con Google

## Overview

Implementación básica de autenticación con Google y manejo de cookies y headers para autorización de rutas protegidas

## Getting Started

### Step 1: Renombra env.example a .env

Rename the `env.example` file to `.env` to configure environment variables for your application.

```bash
mv env.example .env
```

### Step 2: Edit .env to add the key values
### Step 3: To run the program execute:
node server.js

## Forma de uso:
Con un navegador acceder a las siguientes rutas:   
/api/protected <--- debe desplegar el mensaje "Not Authorized"   
/login <--- despliega botón de login y realiza la autenticación con google   
/api/protected <--- Si la autenticación fue exitosa debe desplegar los datos del profile de google   

Debe desplegar el objeto de datos recibido de Google