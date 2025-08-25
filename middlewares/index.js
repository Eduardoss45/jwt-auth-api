// * middlewares
function checkEmptyBody(req, res, next) {
  const methodsWithBody = ['POST', 'PUT', 'PATCH'];

  if (methodsWithBody.includes(req.method)) {
    if (!req.body || Object.keys(req.body).length === 0) {
      return res.status(400).json({ msg: 'Corpo da requisição está vazio' });
    }
  }

  next();
}

function checkToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ msg: 'Acesso negado!' });
  }

  try {
    const secret = process.env.ACCESS_SECRET;
    jwt.verify(token, secret);
    next();
  } catch (error) {
    res.status(400).json({ msg: 'Token inválido!' });
  }
}

// * exportando middlewares
module.exports = { checkEmptyBody, checkToken };
