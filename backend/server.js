const express = require("express");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const { body, validationResult } = require("express-validator");
const admin = require("firebase-admin");

const serviceAccount = JSON.parse(process.env.FIREBASE);

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();
const usersCollection = db.collection("users");

const app = express();
app.use(express.json());
app.use(cors());

const SECRET_KEY = process.env.SECRET_KEY || "supersecret";

const loginLimiter = rateLimit({
    windowMs: 30 * 1000,
    max: 5,
    message: "Too many login attempts. Try again in 30 seconds.",
    headers: true
});

app.post(
    "/signup",
    [body("username").trim().escape(), body("password").isLength({ min: 6 }).escape()],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

        const { username, password } = req.body;
        const userRef = usersCollection.doc(username);
        const userDoc = await userRef.get();

        if (userDoc.exists) return res.status(400).json({ message: "Username already exists" });

        const hashedPassword = await bcrypt.hash(password, 10);
        await userRef.set({ password: hashedPassword });

        res.json({ success: true, message: "Account created successfully!" });
    }
);

app.post(
    "/login",
    loginLimiter,
    [body("username").trim().escape(), body("password").escape()],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

        const { username, password } = req.body;
        const userRef = usersCollection.doc(username);
        const userDoc = await userRef.get();

        if (!userDoc.exists) return res.status(401).json({ message: "Invalid credentials" });

        const userData = userDoc.data();
        const validPassword = await bcrypt.compare(password, userData.password);

        if (!validPassword) return res.status(401).json({ message: "Invalid credentials" });

        const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: "1h" });

        res.json({ success: true, message: "Login successful", token });
    }
);

app.get("/", (req, res) => {
    res.send("Backend is running!");
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
