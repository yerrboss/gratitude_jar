import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

const JWT_SECRET = process.env.JWT_SECRET || "SUPER_SECRET_REPLACE_THIS";
const mongoURI = process.env.MONGO_URI || 'mongodb://localhost:27017/gratitude_jar';

mongoose.connect(mongoURI)
  .then(() => console.log("✅ Successfully connected to MongoDB"))
  .catch(err => console.error("❌ MongoDB Connection Error:", err.message));

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  notes: [{ text: String, createdAt: { type: Date, default: Date.now } }]
});

const User = mongoose.model("User", userSchema);

// Middleware to protect routes
const authenticate = async (req, res, next) => {
  try {
    const token = req.headers.authorization;
    if (!token) return res.status(401).send("No token provided");
    const cleanToken = token.startsWith("Bearer ") ? token.split(" ")[1] : token;
    const decoded = jwt.verify(cleanToken, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (e) {
    res.status(401).send("Invalid session");
  }
};

// Auth Routes
app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword });
    await user.save();
    res.status(201).send("User created");
  } catch (e) { res.status(400).send("Username taken"); }
});

app.post("/login", async (req, res) => {
  const user = await User.findOne({ username: req.body.username });
  if (user && await bcrypt.compare(req.body.password, user.password)) {
    const token = jwt.sign({ userId: user._id }, JWT_SECRET);
    res.json({ token });
  } else { res.status(401).send("Invalid credentials"); }
});

// Notes Routes
app.get("/notes", authenticate, async (req, res) => {
  const user = await User.findById(req.userId);
  res.json(user.notes || []);
});

app.post("/notes", authenticate, async (req, res) => {
  if (!req.body.text) return res.status(400).send("Empty note");
  const user = await User.findById(req.userId);
  user.notes.push({ text: req.body.text });
  await user.save();
  res.json(user.notes);
});

// EDIT/UPDATE ROUTE
app.put("/notes/:id", authenticate, async (req, res) => {
  const user = await User.findById(req.userId);
  const note = user.notes.id(req.params.id);
  if (note) {
    note.text = req.body.newText || req.body.text;
    await user.save();
    res.sendStatus(200);
  } else { res.status(404).send("Note not found"); }
});

// DELETE ROUTE
app.delete("/notes/:id", authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    user.notes.pull({ _id: req.params.id });
    await user.save();
    res.sendStatus(200);
  } catch (e) { res.status(500).send("Delete failed"); }
});

const PORT = 5000;
app.listen(PORT, () => console.log(`🚀 Server on http://localhost:${PORT}`));