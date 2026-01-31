const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const cors = require("cors");
require("dotenv").config();

const User = require("./models/User");
const Scan = require("./models/Scan");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static("public"));

mongoose.connect(process.env.MONGO_URI)
.then(() => console.log("✅ MongoDB Connected"))
.catch(err => console.log(err));

// 🔍 Scam Detection Logic
function detectScam(text) {
  const scamKeywords = [
    "urgent", "verify", "otp", "account blocked",
    "click link", "free reward", "limited time"
  ];

  let score = 0;
  scamKeywords.forEach(word => {
    if (text.toLowerCase().includes(word)) score += 15;
  });

  if (text.includes("bit.ly") || text.includes("tinyurl")) score += 25;

  let result = "SAFE";
  if (score >= 40) result = "SCAM";
  else if (score >= 20) result = "SUSPICIOUS";

  return { result, confidence: Math.min(score + 30, 95) };
}

// 🧑 Register
app.post("/api/register", async (req, res) => {
  const { name, email, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  await User.create({ name, email, password: hashed });
  res.json({ message: "User registered" });
});

// 🔐 Login
app.post("/api/login", async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user) return res.status(400).json({ error: "User not found" });

  const isMatch = await bcrypt.compare(req.body.password, user.password);
  if (!isMatch) return res.status(400).json({ error: "Wrong password" });

  res.json({ message: "Login success", userId: user._id });
});

// 🔍 Scan API
app.post("/api/scan", async (req, res) => {
  const { userId, input } = req.body;
  const analysis = detectScam(input);

  await Scan.create({
    userId,
    input,
    result: analysis.result,
    confidence: analysis.confidence
  });

  res.json(analysis);
});

// 📜 History
app.get("/api/history/:id", async (req, res) => {
  const data = await Scan.find({ userId: req.params.id });
  res.json(data);
});

app.listen(5000, () =>
  console.log("🚀 Server running at http://localhost:5000")
);
