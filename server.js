const express = require('express');
const app = express();
const pool = require('./db');
const cors = require('cors');
const bcrypt = require('bcrypt');
require('dotenv').config();

app.use(express.json());
// Allow requests from frontend (http://localhost:3000)
app.use(cors({
  origin: "http://localhost:3000",
  methods: "GET, POST",
  allowedHeaders: "Content-Type, Authorization"
}));

const PORT = 5000;

app.get("/", (req, res) => {
    return res.json({message: "Hey! I am in nodejs container v2."});
})

app.get("/users", async (req,res) => {
    try {
        const result = await pool.query("SELECT * FROM users");
        res.json(result.rows);
      } catch (err) {
        console.error(err.message);
        res.status(500).send("Server Error");
      }
});


app.post("/signup", async (req, res) => {
const { username, email, password } = req.body;

  // Hash the password before storing it
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const result = await pool.query(
      "INSERT INTO users (user_name, user_email, user_password) VALUES ($1, $2, $3) RETURNING *",
      [username, email, hashedPassword]
    );
    
    res.status(201).json({ message: "User registered successfully", user: result.rows[0] });
  } catch (err) {
    console.log('Error:', err);
    res.status(500).json({ message: "Error registering user", error: err.message });
  }
});


app.listen(PORT, () => console.log(`Server running on PORT: ${PORT}`));