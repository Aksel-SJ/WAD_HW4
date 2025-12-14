require("dotenv").config();
const express = require("express");
const cors = require("cors");
const pool = require("./db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const auth = require("./middleware/auth");

const app = express();
app.use(cors());
app.use(express.json());

/* ---------- DATABASE SETUP ---------- */
const initializeDatabase = async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email VARCHAR(255) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS posts (
      id SERIAL PRIMARY KEY,
      body TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  console.log("Tables ready");
};

initializeDatabase();

/* ---------- AUTH ---------- */
app.post("/signup", async (req, res) => {
  try {
    const { email, password } = req.body;

    const exists = await pool.query(
      "SELECT 1 FROM users WHERE email=$1",
      [email]
    );

    if (exists.rows.length > 0) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      "INSERT INTO users (email, password) VALUES ($1,$2) RETURNING id",
      [email, hashedPassword]
    );

    const token = jwt.sign(
      { id: result.rows[0].id },
      process.env.JWT_SECRET
    );

    res.json({ token });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query(
      "SELECT * FROM users WHERE email=$1",
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password);

    if (!valid) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user.id },
      process.env.JWT_SECRET
    );

    res.json({ token });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

/* ---------- POSTS (PROTECTED) ---------- */
app.get("/posts", auth, async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM posts ORDER BY created_at DESC"
  );
  res.json(result.rows);
});

app.get("/posts/:id", auth, async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM posts WHERE id=$1",
    [req.params.id]
  );
  res.json(result.rows[0]);
});

app.post("/posts", auth, async (req, res) => {
  const { body } = req.body;

  const result = await pool.query(
    "INSERT INTO posts (body) VALUES ($1) RETURNING *",
    [body]
  );

  res.json(result.rows[0]);
});

app.put("/posts/:id", auth, async (req, res) => {
  const { body } = req.body;

  await pool.query(
    "UPDATE posts SET body=$1 WHERE id=$2",
    [body, req.params.id]
  );

  res.json({ message: "Updated" });
});

app.delete("/posts/:id", auth, async (req, res) => {
  await pool.query(
    "DELETE FROM posts WHERE id=$1",
    [req.params.id]
  );

  res.json({ message: "Deleted" });
});

app.delete("/posts", auth, async (req, res) => {
  await pool.query("DELETE FROM posts");
  res.json({ message: "All posts deleted" });
});

/* ---------- SERVER ---------- */
app.listen(process.env.PORT, () => {
  console.log(`Server running on port ${process.env.PORT}`);
});
