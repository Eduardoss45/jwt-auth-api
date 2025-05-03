require("dotenv").config();
const { User } = require("../models");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");

// * controllers
function welcomeController(req, res) {
    res.status(200).json({ msg: "Bem vindo a nossa API!" });
};

async function registerController(req, res) {
    const { name, email, password, confirmpassword } = req.body;

    if (!name || !email || !password || !confirmpassword) {
        return res.status(422).json({ msg: "Certifique que os campos name, email, password e confirmpassword foram enviados." });
    };

    if (password !== confirmpassword) {
        return res.status(422).json({ msg: "As senhas não conferem!" });
    };

    const userExists = await User.findOne({ email: email });

    if (userExists) {
        return res.status(422).json({ msg: "Por favor, utilize outro e-mail!" });
    };

    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    const user = new User({
        name,
        email,
        password: passwordHash,
    });

    try {
        await user.save();
        res.status(201).json({ msg: "Usuário criado com sucesso!" });
    } catch (error) {
        console.log(err);
        res.status(500).json({ msg: "Aconteceu um erro no servidor, tente novamente mais tarde!" });
    };
};

async function loginController(req, res) {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(422).json({ msg: "Certifique que os campos email e password foram enviados." });
    };

    const user = await User.findOne({ email: email });
    if (!user) {
        return res.status(422).json({ msg: "Usuário não encontrado!" });
    };

    const checkPassword = await bcrypt.compare(password, user.password);
    if (!checkPassword) {
        return res.status(422).json({ msg: "Senha inválida!" });
    }

    try {
        const secret = process.env.SECRET;
        const token = jwt.sign({
            id: user._id
        },
            secret,
        );

        res.status(200).json({ msg: "Autenticação realizada com sucesso", token });
    } catch (err) {
        console.log(err);
        res.status(500).json({ msg: "Aconteceu um erro no servidor, tente novamente mais tarde!" });
    }

};

async function userController(req, res) {
    const id = req.params.id;

    if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({ msg: "ID inválido!" });
    }

    const user = await User.findById(id, "-password -__v");

    if (!user) {
        return res.status(404).json({ msg: "Usuário não encontrado" });
    };

    res.status(200).json({ user });
};

// * exportando controllers
module.exports = { welcomeController, registerController, loginController, userController };