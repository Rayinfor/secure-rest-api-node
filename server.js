const fs = require("fs");
const path = require("path");
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME_SECRET";
const DB_PATH = path.join(__dirname, "db.json");

// Limit simple: 60 requêtes / minute / IP
const limiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 60,
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);

function readDb() {
  const raw = fs.readFileSync(DB_PATH, "utf-8");
  return JSON.parse(raw);
}

function writeDb(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}

function isValidEmail(email) {
  return typeof email === "string" && email.includes("@") && email.length <= 100;
}

function isValidPassword(pw) {
  return typeof pw === "string" && pw.length >= 8 && pw.length <= 200;
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || "";
  const parts = header.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") {
    return res.status(401).json({ error: "Missing or invalid Authorization header" });
  }

  try {
    const payload = jwt.verify(parts[1], JWT_SECRET);
    req.user = payload;
    return next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

app.get("/", (req, res) => {
  res.json({ ok: true, service: "secure-api-node" });
});

app.post("/auth/register", (req, res) => {
  const { email, password } = req.body;

  if (!isValidEmail(email) || !isValidPassword(password)) {
    return res.status(400).json({ error: "Invalid email or password (min 8 chars)" });
  }

  const db = readDb();
  const exists = db.users.find(u => u.email === email);
  if (exists) {
    return res.status(409).json({ error: "Email already registered" });
  }

  const hash = bcrypt.hashSync(password, 10);
  db.users.push({ id: Date.now(), email, passwordHash: hash });
  writeDb(db);

  return res.status(201).json({ message: "User created" });
});

app.post("/auth/login", (req, res) => {
  const { email, password } = req.body;

  const db = readDb();
  const user = db.users.find(u => u.email === email);
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const ok = bcrypt.compareSync(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });

  const token = jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, { expiresIn: "1h" });
  return res.json({ token });
});

app.get("/me", authMiddleware, (req, res) => {
  res.json({ user: req.user });
});

app.get("/secure/data", authMiddleware, (req, res) => {
  res.json({ secretData: "Only authenticated users can see this." });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log("Tip: set JWT_SECRET in your environment for production.");
});