const express = require("express")
const router = express.Router();
const { checkEmptyBody, checkToken } = require("../middlewares");
const { welcomeController, registerController, loginController, userController } = require("../controllers");

// * rotas

// * publico
router.get("/", welcomeController);
router.post("/auth/register", checkEmptyBody, registerController);
router.post("/auth/login", checkEmptyBody, loginController);

// * privado
router.get("/user/:id", checkToken, userController);

// * exportando rotas
module.exports = router;