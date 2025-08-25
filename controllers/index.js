// * imports
const { User } = require('../models/userModel');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const generateCode = require('../utils/generateCode');
const transporter = require('../services/transporter');

// * controllers
function welcomeController(req, res) {
  res.status(200).json({ msg: 'Bem vindo a nossa API!' });
}

async function registerController(req, res) {
  const { name, email, password, confirmpassword } = req.body;

  if (!name || !email || !password || !confirmpassword) {
    return res.status(422).json({
      msg: 'Certifique que os campos name, email, password e confirmpassword foram enviados.',
    });
  }

  if (password !== confirmpassword) {
    return res.status(422).json({ msg: 'As senhas não conferem!' });
  }

  const userExists = await User.findOne({ email: email });

  if (userExists) {
    return res.status(422).json({ msg: 'Por favor, utilize outro e-mail!' });
  }

  const salt = await bcrypt.genSalt(12);
  const passwordHash = await bcrypt.hash(password, salt);
  const data = generateCode();

  const user = new User({
    name,
    email,
    password: passwordHash,
    codeHash: data.codeHash,
    codeExpiresAt: data.codeExpiresAt,
    verified: false,
  });

  try {
    await user.save();
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Verificação de e-mail',
      text: `Seu código de verificação é: ${data.code}`,
    });
    res.status(201).json({ msg: `código de verificação enviado para ${email}!` });
  } catch (error) {
    console.log('Erro ao enviar e-mail:', error);
    res.status(500).json({ msg: 'Aconteceu um erro no servidor, tente novamente mais tarde!' });
  }
}

async function loginController(req, res) {
  const { email, password, code } = req.body;

  if (!email || !password) {
    return res
      .status(422)
      .json({ msg: 'Certifique que os campos email e password foram enviados.' });
  }

  const user = await User.findOne({ email: email });
  if (!user) {
    return res.status(422).json({ msg: 'Usuário não encontrado!' });
  }

  if (user.verified === false) {
    if (!code) {
      return res.status(422).json({ msg: 'Envie o código de verificação!' });
    }

    if (!user.codeHash || user.codeExpiresAt.getTime() < Date.now()) {
      return res.status(422).json({ msg: 'Código expirado. Solicite outro.' });
    }

    user.codeAttempts = (user.codeAttempts || 0) + 1;

    if (user.codeAttempts > 5) {
      return res.status(429).json({ msg: 'Muitas tentativas. Aguarde e gere outro código.' });
    }

    const ok = await bcrypt.compare(code.trim().toUpperCase(), user.codeHash);

    if (!ok) return res.status(422).json({ msg: 'Código inválido!' });

    user.codeHash = undefined;
    user.codeExpiresAt = undefined;
    user.codeAttempts = 0;
    user.verified = true;
    await user.save();
  }

  const checkPassword = await bcrypt.compare(password, user.password);
  if (!checkPassword) {
    return res.status(422).json({ msg: 'Senha inválida!' });
  }

  try {
    const access_secret = process.env.ACCESS_SECRET;
    const refresh_secret = process.env.REFRESH_SECRET;
    const payload = {
      id: user._id,
      email: user.email,
    };
    const token = jwt.sign(payload, access_secret, { expiresIn: '15m' });
    const refreshToken = jwt.sign(payload, refresh_secret, { expiresIn: '7d' });
    const refreshHash = bcrypt.hashSync(refreshToken, 12);
    user.refreshTokens.push(refreshHash);
    await user.save();

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.MODE === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.status(200).json({ msg: 'Autenticação e email validados com sucesso', token });
  } catch (err) {
    res.status(500).json({ msg: 'Aconteceu um erro no servidor, tente novamente mais tarde!' });
  }
}

async function refreshToken(req, res) {
  const refreshToken = req.cookies?.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ error: 'Refresh token não fornecido' });
  }

  try {
    const refresh_secret = process.env.REFRESH_SECRET;
    const decoded = jwt.verify(refreshToken, refresh_secret);

    const user = await User.findById(decoded.id);
    if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });

    const isValid = user.refreshTokens.some(rt => bcrypt.compareSync(refreshToken, rt));

    if (!isValid) {
      return res.status(403).json({ error: 'Refresh token inválido' });
    }

    user.refreshTokens = user.refreshTokens.filter(rt => !bcrypt.compareSync(refreshToken, rt));

    const payload = { id: user._id, email: user.email };

    const newRefreshToken = jwt.sign(payload, refresh_secret, { expiresIn: '7d' });
    const refreshHash = bcrypt.hashSync(newRefreshToken, 12);
    user.refreshTokens.push(refreshHash);
    await user.save();

    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: process.env.MODE === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    const access_secret = process.env.ACCESS_SECRET;
    const token = jwt.sign({ id: user._id, email: user.email }, access_secret, {
      expiresIn: '15m',
    });

    return res.status(200).json({ token });
  } catch (error) {
    return res.status(403).json({ error: 'Refresh token inválido ou expirado' });
  }
}

async function userController(req, res) {
  const id = req.params.id;

  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({ msg: 'ID inválido!' });
  }

  const user = await User.findById(id, '-password -__v');

  if (!user) {
    return res.status(404).json({ msg: 'Usuário não encontrado' });
  }

  res.status(200).json({ user });
}

async function resendCodeController(req, res) {
  const { email } = req.body;

  if (!email) {
    return res.status(422).json({ msg: 'Por favor, envie o email!' });
  }

  const user = await User.findOne({ email: email });
  if (!user) {
    return res.status(404).json({ msg: 'Usuário não encontrado!' });
  }

  if (user.verified) {
    return res.status(422).json({ msg: 'Este usuário já foi verificado!' });
  }

  const now = Date.now();
  const lastSent = user.lastCodeSendAt ? new Date(user.lastCodeSendAt).getTime() : 0;

  if (now - lastSent < 15 * 60 * 1000) {
    return res
      .status(429)
      .json({ msg: 'Você já solicitou um código recentemente. Aguarde alguns minutos.' });
  }

  if (!user.resendWindowStart || now - user.resendWindowStart.getTime() > 60 * 60 * 1000) {
    user.resendWindowStart = new Date(now);
    user.resendAttempts = 0;
  }

  if (user.resendAttempts >= 3) {
    return res.status(429).json({ msg: 'Você atingiu o limite de reenvios por hora.' });
  }
  try {
    const data = generateCode();
    user.codeHash = data.codeHash;
    user.codeExpiresAt = data.codeExpiresAt;
    user.codeAttempts = data.codeAttempts;
    user.lastCodeSendAt = new Date();
    user.resendAttempts++;
    await user.save();
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Verificação de e-mail',
      text: `Seu novo código de verificação é: ${data.code}`,
    });
    res.status(200).json({ msg: `Novo código de verificação enviado para ${email}!` });
  } catch (error) {
    console.log('Erro ao enviar e-mail:', error);
    res.status(500).json({ msg: 'Aconteceu um erro no servidor, tente novamente mais tarde!' });
  }
}

async function logoutController(req, res) {
  const refreshToken = req.cookies?.refreshToken;
  if (!refreshToken) return res.sendStatus(204);

  const user = await User.findOne({ refreshTokens: { $exists: true } });
  if (!user) return res.sendStatus(204);

  user.refreshTokens = user.refreshTokens.filter(rt => !bcrypt.compareSync(refreshToken, rt));
  await user.save();

  res.clearCookie('refreshToken', {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.MODE === 'production',
  });
  res.sendStatus(204);
}

// * exports
module.exports = {
  welcomeController,
  registerController,
  loginController,
  refreshToken,
  userController,
  resendCodeController,
  logoutController,
};
