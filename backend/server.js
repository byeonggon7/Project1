const express = require("express");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const { body, validationResult } = require("express-validator");

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
    headers: true
});

app.post(
    "/signup",
    [body("username").trim().escape(), body("password").isLength({ min: 6 }).escape()],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

        const { username, password } = req.body;
        if (users[username]) return res.status(400).json({ message: "Username already exists" });

        const hashedPassword = await bcrypt.hash(password, 10);
        users[username] = { password: hashedPassword };

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

        if (!failedAttempts[username]) failedAttempts[username] = { count: 0, lastAttempt: Date.now() };
        if (failedAttempts[username].count >= 5 && Date.now() - failedAttempts[username].lastAttempt < 30000)
            return res.status(429).json({ message: "Too many login attempts. Try again in 30 seconds." });

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
    }
);

app.get("/", (req, res) => {
    res.send("Backend is running!");
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

