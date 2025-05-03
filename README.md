# JWT Auth API

Uma API de autenticação simples utilizando **Node.js**, **Express**, **MongoDB**, **Mongoose** e **JWT (JSON Web Tokens)**.

## 🔐 Funcionalidades

- Registro de usuários
- Login com geração de token JWT
- Rota protegida acessível apenas com token válido
- Hash de senha com Bcrypt
- Middleware para verificação de token

---

## 📁 Estrutura

```
jwt-auth-api/
├── controllers/
├── db/
├── middlewares/
├── models/
├── routes/
├── .env
├── app.js
├── package.json
```

---

## 🛠️ Tecnologias

- Node.js
- Express
- MongoDB
- Mongoose
- Bcrypt
- JSON Web Token (JWT)
- dotenv

---

## 📦 Instalação

```bash
git clone https://github.com/Eduardoss45/jwt-auth-api.git
cd jwt-auth-api
npm install
```

Crie um arquivo `.env` na raiz com as seguintes variáveis:

```env
DB_USER=seu_usuario_mongodb
DB_PASS=sua_senha_mongodb
SECRET=uma_chave_secreta_segura
```

---

## ▶️ Execução

```bash
npm run start
```

A API estará disponível em: `http://localhost:3000`

---

## 📌 Rotas

### ✅ Rota pública

- `GET /`  
  Retorna mensagem de boas-vindas.

---

### 📝 Registrar usuário

- `POST /auth/register`  
  Cria um novo usuário.

**Body JSON:**
```json
{
  "name": "João",
  "email": "joao@email.com",
  "password": "123456",
  "confirmpassword": "123456"
}
```

---

### 🔐 Login

- `POST /auth/login`  
  Autentica o usuário e retorna um token JWT.

**Body JSON:**
```json
{
  "email": "joao@email.com",
  "password": "123456"
}
```

**Resposta:**
```json
{
  "msg": "Autenticação realizada com sucesso!",
  "token": "JWT_TOKEN"
}
```

---

### 🔒 Rota protegida

- `GET /user/:id`  
  Acessível apenas com token válido no header `Authorization`.

**Exemplo de header:**
```
Authorization: Bearer JWT_TOKEN
```

---

## 🧪 Testando

Você pode testar usando o [Postman](https://www.postman.com/) ou [Insomnia](https://insomnia.rest/).

---

## 📄 Licença

Este projeto está sob a licença MIT.
