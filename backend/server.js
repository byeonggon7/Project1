const express = require("express");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

const users = {};
const SECRET_KEY = process.env.SECRET_KEY || "supersecret";

const failedAttempts = {};

const loginLimiter = rateLimit({
    windowMs: 30 * 1000,
    max: 5,
    message: "Too many login attempts. Try again in 30 seconds.",
    headers: true,
});

app.post("/login", loginLimiter, async (req, res) => {
    const { username, password } = req.body;

    if (!failedAttempts[username]) {
        failedAttempts[username] = { count: 0, lastAttempt: Date.now() };
    }

    if (failedAttempts[username].count >= 5 && Date.now() - failedAttempts[username].lastAttempt < 30000) {
        return res.status(429).json({ message: "Too many login attempts. Try again in 30 seconds." });
    }

    if (!users[username]) {
        failedAttempts[username].count += 1;
        failedAttempts[username].lastAttempt = Date.now();
        return res.status(401).json({ message: "Invalid credentials" });
    }

    const validPassword = await bcrypt.compare(password, users[username].password);
    if (!validPassword) {
        failedAttempts[username].count += 1;
        failedAttempts[username].lastAttempt = Date.now();
        return res.status(401).json({ message: "Invalid credentials" });
    }

    failedAttempts[username].count = 0;
    const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: "1h" });
    res.json({ success: true, message: "Login successful", token });
});

app.get("/", (req, res) => {
    res.send("Backend is running!");
});

app.listen(5000, () => console.log("Server running on port 5000"));
