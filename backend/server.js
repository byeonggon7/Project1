const express = require("express");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const { body, validationResult } = require("express-validator");
const admin = require("firebase-admin");

const path = require("path");
const serviceAccount = require(path.join(__dirname, "serviceaccountkey.json"));

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();
const usersCollection = db.collection("users");

const app = express();
app.set('trust proxy', 1);
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
    [body("username").trim().notEmpty(), body("password").isLength({ min: 6 }).notEmpty()],
    async (req, res) => {
        console.log("Signup request received:", req.body);

        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            console.log("Validation errors:", errors.array());
            return res.status(400).json({ errors: errors.array() });
        }

        const { username, password } = req.body;
        console.log("Checking if user exists:", username);

        const userRef = usersCollection.doc(username);
        const userDoc = await userRef.get();

        if (userDoc.exists) {
            console.log("User already exists:", username);
            return res.status(400).json({ message: "Username already exists" });
        }

        try {
            const hashedPassword = await bcrypt.hash(password, 10);
            await userRef.set({ password: hashedPassword });
            console.log("User successfully added to Firestore:", username);

            res.json({ success: true, message: "Account created successfully!" });
        } catch (error) {
            console.error("Error writing to Firestore:", error);
            res.status(500).json({ message: "Internal server error" });
        }
    }
);

app.post(
    "/login",
    loginLimiter,
    [body("username").trim().escape(), body("password").escape()],
    async (req, res) => {
        console.log("Login request received:", req.body);

        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            console.log("Validation errors:", errors.array());
            return res.status(400).json({ errors: errors.array() });
        }

        const { username, password } = req.body;
        console.log("Checking user:", username);

        const userRef = usersCollection.doc(username);
        const userDoc = await userRef.get();

        if (!userDoc.exists) {
            console.log("User not found:", username);
            return res.status(401).json({ message: "Invalid credentials" });
        }

        const userData = userDoc.data();
        console.log("Stored user data:", userData);

        const validPassword = await bcrypt.compare(password, userData.password);
        if (!validPassword) {
            console.log("Password does not match for:", username);
            return res.status(401).json({ message: "Invalid credentials" });
        }

        const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: "1h" });
        console.log("Login successful for:", username);

        res.json({ success: true, message: "Login successful", token });
    }
);

app.get("/", (req, res) => {
    res.send("Backend is running!");
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
