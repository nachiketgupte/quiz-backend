const express = require('express');
const app = express();
const pool = require('./db');
const cors = require('cors');
const bcrypt = require('bcrypt');
const { body, validationResult } = require("express-validator");
require('dotenv').config();

app.use(express.json());
// Allow requests from frontend (http://localhost:3000)
app.use(cors({
  origin: "http://localhost:3000",
  credentials: true,
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

app.post(
  "/signup",
  [
    body("username")
      .trim()
      .isLength({ min: 3 })
      .withMessage("Username must be at least 3 characters long")
      .matches(/^[a-zA-Z0-9_]+$/)
      .withMessage("Username can only contain letters, numbers, and underscores"),
    body("email").isEmail().normalizeEmail().withMessage("Invalid email address"),
    body("password")
      .isLength({ min: 6 })
      .withMessage("Password must be at least 6 characters long")
      .matches(/[0-9]/)
      .withMessage("Password must contain at least one number")
      .matches(/[!@#$%^&*]/)
      .withMessage("Password must contain at least one special character (!@#$%^&*)"),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, email, password } = req.body;

    try {
      // Hash the password before storing it
      const hashedPassword = await bcrypt.hash(password, 10);

      const checkUserExists = await pool.query(
        "SELECT COUNT(*) AS count FROM users WHERE user_name = $1",
        [username]
      );
      
      if (parseInt(checkUserExists.rows[0].count) > 0) { // Convert to integer
        return res.status(400).json({ message: "Username already exists" });
      }
      
      const checkEmailExists = await pool.query(
        "SELECT COUNT(*) AS count FROM users WHERE user_email = $1",
        [email]
      );
      
      if (parseInt(checkEmailExists.rows[0].count) > 0) { // Convert to integer
        return res.status(400).json({ message: "Email already exists" });
      }      

      const result = await pool.query(
        "INSERT INTO users (user_name, user_email, user_password) VALUES ($1, $2, $3) RETURNING *",
        [username, email, hashedPassword]
      );

      res.status(201).json({ message: "User registered successfully", user: result.rows[0] });
    } catch (err) {
      console.error("Error:", err);

      if (err.code === "23505") {
        return res.status(400).json({ message: "Username already exists" });
      }

      res.status(500).json({ message: "Error registering user", error: err.message });
    }
  }
);


app.post("/login", async (req, res) => {
  const {username, password} = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const result = await pool.query(
    "SELECT COUNT(*) FROM USERS WHERE user_name = $1 and user_password = $2",
    [username, hashedPassword]
  );
  console.log('Login request');
  
  if(result.rowCount === 0)
  {
    return res.status(401).json({ message: "Invalid credentials" });
  }
  
  return res.status(200).json({message: "Login successful"});
  
})

app.listen(PORT, () => console.log(`Server running on PORT: ${PORT}`));