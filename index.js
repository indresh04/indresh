require("dotenv").config();
const express = require("express");
const crypto = require("crypto");
const bodyParser = require("body-parser");
const path = require("path");
// wcsdaxas
const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.set("view engine", "ejs");
app.use(express.static(path.join(__dirname, "public"))); // Serve static files

const fs = require("fs");


// Load RSA 4096 keys from files
const publicKey = fs.readFileSync(path.join(__dirname, "public.pem"), "utf8");
const privateKey = fs.readFileSync(path.join(__dirname, "private.pem"), "utf8");

// const publicKey = process.env.PUBLIC_KEY.replace(/\\n/g, "\n");
// const privateKey = process.env.PRIVATE_KEY.replace(/\\n/g, "\n");

// Render the EJS form
app.get("/", (req, res) => {
    res.render("index", { encryptedData: null, decryptedData: null, error: null });
});


// Route to display RSA keys
// app.get("/keys", (req, res) => {
//     res.send(`
//         <h1>RSA Public & Private Keys</h1>
//         <h3>Public Key:</h3>
//         <pre>${publicKey}</pre>
//         <h3>Private Key:</h3>
//         <pre>${privateKey}</pre>
//     `);
// });


// Handle Encryption
app.post("/encrypt", (req, res) => {
    try {
        const { data } = req.body;
        if (!data) return res.render("index", { encryptedData: null, decryptedData: null, error: "No data provided" });

        const encryptedData = crypto.publicEncrypt(
            {
                key: publicKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: "sha256",
            },
            Buffer.from(data)
        );

        res.render("index", { encryptedData: encryptedData.toString("base64"), decryptedData: null, error: null });
    } catch (error) {
        res.render("index", { encryptedData: null, decryptedData: null, error: error.message });
    }
});

// Handle Decryption
app.post("/decrypt", (req, res) => {
    try {
        const { encryptedData } = req.body;
        if (!encryptedData) return res.render("index", { encryptedData: null, decryptedData: null, error: "No encrypted data provided" });

        const decryptedData = crypto.privateDecrypt(
            {
                key: privateKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: "sha256",
            },
            Buffer.from(encryptedData, "base64")
        );

        res.render("index", { encryptedData: null, decryptedData: decryptedData.toString(), error: null });
    } catch (error) {
        res.render("index", { encryptedData: null, decryptedData: null, error: error.message });
    }
});

app.listen(3000, () => console.log(`Server running on http://localhost:${PORT}`));
