import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import cors from "cors";
import crypto from "crypto";
import dotenv from "dotenv";
dotenv.config();

const app = express();
const port = 3000;
const SECRET_KEY = process.env.SECRET_KEY;

// PostgreSQL connection
const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "permalist",
  password: "1234", // Consider using process.env.DB_PASSWORD in production
  port: 5432,
});
db.connect();

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

// Nodemailer setup
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "No token provided" });
  }

  jwt.verify(token, process.env.SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Invalid or expired token" });
    }

    console.log("Authenticated user:", user); // Log the decoded token payload
    req.user = user; // ✅ Directly assign
    next();
  });
}



// Signup Route
app.post("/api/auth/signup", async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const existingUser = await db.query("SELECT * FROM users WHERE username = $1", [username]);
    if (existingUser.rows.length > 0)
      return res.status(400).json({ error: "Username already taken" });

    const existingEmail = await db.query("SELECT * FROM users WHERE email = $1", [email]);
    if (existingEmail.rows.length > 0)
      return res.status(400).json({ error: "Email already registered" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const verification_token = crypto.randomBytes(32).toString("hex");

    await db.query(
      `INSERT INTO users (username, email, password, verification_token)
       VALUES ($1, $2, $3, $4)`,
      [username, email, hashedPassword, verification_token]
    );

    const verifyLink = `http://localhost:3000/api/verify/${verification_token}`;
    await transporter.sendMail({
      from: '"Todo App" <no-reply@todo.com>',
      to: email,
      subject: "Verify your account",
      html: `<p>Click the link to verify your account:</p><a href="${verifyLink}">${verifyLink}</a>`,
    });

    res.status(200).json({ message: "Signup successful! Check your email to verify your account." });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Email Verification Route
app.get("/api/verify/:token", async (req, res) => {
  const token = req.params.token;

  try {
    const result = await db.query("SELECT * FROM users WHERE verification_token = $1", [token]);

    if (result.rows.length === 0) {
      return res.redirect("http://localhost:5500/auth/emailInvalid.html");
    }

    await db.query(
      `UPDATE users
       SET is_verified = TRUE, verification_token = NULL
       WHERE verification_token = $1`,
      [token]
    );

    res.redirect("http://localhost:5500/auth/emailVerified.html");
  } catch (err) {
    res.status(500).send("Server error.");
  }
});

// Login Route
app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await db.query("SELECT * FROM users WHERE username = $1", [username]);
    if (result.rows.length === 0)
      return res.status(400).json({ error: "Invalid email or username." });

    const user = result.rows[0];
    if (!user.is_verified)
      return res.status(400).json({ error: "Email not verified." });

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid)
      return res.status(400).json({ error: "Invalid password." });

  const token = jwt.sign({ user_id: user.id }, SECRET_KEY, { expiresIn: "7d" });

    res.json({ message: "Login successful", token });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error." });
  }
});

// Get all user items
app.get("/api/items", authenticateToken, async (req, res) => {
  try {
    const result = await db.query(
      "SELECT * FROM items WHERE user_id = $1 ORDER BY id ASC",
      [req.user.user_id]

    );

    console.log("Fetched todos from DB:", result.rows);  // Log the data from the database
    res.json(result.rows);
  } catch (err) {
    console.error("Error fetching todos:", err);
    res.status(500).json({ error: err.message });
  }
});


// Add item
app.post("/api/items", authenticateToken, async (req, res) => {
  const { title, status, start_time, end_time, comment } = req.body;

  try {
    // Log the userId (from JWT token) that is being used to insert the todo
    console.log("Inserting todo with user_id:", req.user.user_id);  // ✅ correct


    const result = await db.query(
      `INSERT INTO items (title, status, start_time, end_time, comment, user_id)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [title, status || false, start_time, end_time, comment, req.user.user_id]

    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// Update item
app.put("/api/items/:id", authenticateToken, async (req, res) => {
  const { title, status, start_time, end_time, comment } = req.body;
  const { id } = req.params;

  try {
    const result = await db.query(
      `UPDATE items
       SET title = $1, status = $2, start_time = $3, end_time = $4, comment = $5
       WHERE id = $6 AND user_id = $7`,
      [title, status, start_time, end_time, comment, id, req.user.user_id]
    );

    if (result.rowCount > 0) {
      res.json({ success: true });
    } else {
      res.status(404).json({ error: "Item not found or no changes made" });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete item
app.delete("/api/items/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    await db.query("DELETE FROM items WHERE id = $1 AND user_id = $2", [id, req.user.user_id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Start server
app.listen(port, () => {
  console.log(`✅ Server running on http://localhost:${port}`);
});
