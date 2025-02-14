const Redis = require("ioredis");
const redis = new Redis();
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

const loginLimiter = rateLimit({
    windowMs: 30 * 1000,
    max: 5,
    message: "Too many login attempts. Try again in 30 seconds.",
    headers: true,
});

app.post("/login", loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    const key = `failed_attempts:${username}`;

    let attempts = await redis.get(key) || 0;
    attempts = parseInt(attempts);

    if (attempts >= 5) {
        return res.status(429).send("Too many login attempts. Try again in 30 seconds.");
    }

    if (!users[username]) {
        await redis.incr(key);
        await redis.expire(key, 30);
        return res.status(401).json({ message: "Invalid credentials" });
    }

    const validPassword = await bcrypt.compare(password, users[username].password);
    if (!validPassword) {
        await redis.incr(key);
        await redis.expire(key, 30);
        return res.status(401).json({ message: "Invalid credentials" });
    }

    await redis.del(key);
    const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: "1h" });
    res.json({ success: true, message: "Login successful", token });
});

app.listen(5000, () => console.log("Server running on port 5000"));
