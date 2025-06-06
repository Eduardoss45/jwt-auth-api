// * imports
const express = require("express");
const app = express();
const port = 3000;
const connectDB = require('./db');
const router = require("./routes");

// * middlewares 
app.use(express.json());
app.use("/", router);

(async () => {
    const connected = await connectDB()
    if (connected) {
        app.listen(port, () => {
            console.log(`Servidor rodando na porta: ${port}`)
        })
    } else {
        console.error("Erro na conexão com o banco. Servidor não iniciado.");
    }
})();