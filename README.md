# JWT Auth API

Uma API de autenticação simples utilizando **Node.js**, **Express**, **MongoDB** e **JWT (JSON Web Tokens)**.

---

## 🔐 Funcionalidades

- Registro de usuários
- Login com validação de e-mail + geração de **accessToken** e **refreshToken**
- Reenvio de código de verificação
- Rota protegida acessível apenas com token válido
- Logout removendo refresh token
- Hash de dados sensíveis com **Bcrypt**
- Middleware para verificação de token
- Refresh token via cookie **httpOnly** e **secure**

---

## 📁 Estrutura

```

jwt-auth-api/
├── controllers/
├── db/
├── middlewares/
├── models/
├── routes/
├── services/
├── utils/
├── .env
├── app.js
├── package.json

```

---

## 🛠️ Tecnologias

- Node.js
- Express
- MongoDB / Mongoose
- Bcrypt
- Cookie-Parser
- JSON Web Token (JWT)
- Dotenv
- Nodemailer

---

## 📦 Instalação

```bash
git clone https://github.com/Eduardoss45/jwt-auth-api.git
cd jwt-auth-api
npm install
```

Crie um arquivo `.env` na raiz com as seguintes variáveis:

```env
DB_USER= # Usuário do banco de dados
DB_PASS= # Senha do banco de dados
ACCESS_SECRET= # Chave de acesso secreta para JWT
REFRESH_SECRET= # Chave de refresh secreta para JWT
EMAIL_USER= # Email do remetente
EMAIL_PASS= # Senha do app de email
MODE= # Modo de operação (development ou production)
```

---

## ▶️ Execução

```bash
npm run start
```

A API estará disponível em: `http://localhost:3000`

---

## 📌 Rotas

### ✅ Rotas Públicas

#### `GET /`

- Retorna mensagem de boas-vindas:

```json
{ "msg": "Bem vindo a nossa API!" }
```

#### `POST /auth/register`

- Cria um novo usuário e envia um **código de verificação** por email.
- **Body:**

```json
{
  "name": "João",
  "email": "joao@email.com",
  "password": "123456",
  "confirmpassword": "123456"
}
```

- Usuário inicia com `verified = false`.

#### `POST /auth/resend-code`

- Reenvia código de verificação para usuários não verificados.
- **Body:**

```json
{ "email": "joao@email.com" }
```

- Limite de reenvios: 3/hora, espera mínima 15 min.
- Substitui código anterior.

#### `POST /auth/login`

- Autentica usuário, valida email e código, retorna **accessToken** e **refreshToken**.
- **Body:**

```json
{
  "email": "joao@email.com",
  "password": "123456",
  "code": "ABC123" // necessário apenas se usuário não estiver verificado
}
```

- `accessToken` enviado no corpo da resposta.
- `refreshToken` enviado em cookie seguro (**httpOnly**, **sameSite=strict**).

#### `POST /auth/refresh`

- Gera novo **accessToken** usando `refreshToken` do cookie.
- Atualiza o `refreshToken` no cookie.

#### `POST /auth/logout`

- Remove o `refreshToken` do banco e limpa o cookie.
- Retorna status `204 No Content`.

---

### 🔒 Rotas Privadas

#### `GET /user/:id`

- Retorna dados do usuário, **excluindo senha**.
- Requer **header**:

```
Authorization: Bearer <accessToken>
```

---

## ⚠️ Segurança

- Senhas e refresh tokens armazenados como hash com **bcrypt**.
- Access token: expira em **15 minutos**.
- Refresh token: expira em **7 dias**, armazenado em cookie seguro.
- Recomendado usar **HTTPS** em produção.
- Limite e expiração para códigos de verificação.
- Emails normalizados (`.toLowerCase()`) para evitar duplicidade.

---

## 🔄 Fluxo Completo de Autenticação

1. `POST /auth/register` → usuário recebe código por email.
2. `POST /auth/login` → envia email, senha e código (se necessário) → recebe **accessToken** e **refreshToken**.
3. Se código não recebido: `POST /auth/resend-code`.
4. `GET /user/:id` → acessa rota protegida com **accessToken**.
5. Quando `accessToken` expira: `POST /auth/refresh` → recebe novo token.
6. Logout: `POST /auth/logout` → remove refreshToken do cookie e banco.

---

## 🧪 Testando

- Use [Postman](https://www.postman.com/) ou [Insomnia](https://insomnia.rest/) para testar todas as rotas.

---

## 📄 Licença

MIT

---

**Autor:** Eduardo Souza
