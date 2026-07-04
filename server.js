const express = require('express')
const cors = require('cors')
const dotenv = require('dotenv')
const Groq = require('groq-sdk')
const mongoose = require('mongoose')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const helmet = require('helmet')
const rateLimit = require('express-rate-limit')

dotenv.config()

// ---- Sanity check required env vars on boot ----
const REQUIRED_ENV = ['MONGODB_URI', 'GROQ_API_KEY', 'JWT_SECRET', 'ADMIN_USERNAME', 'ADMIN_PASSWORD_HASH', 'FRONTEND_ORIGIN']
REQUIRED_ENV.forEach((key) => {
  if (!process.env[key]) {
    console.error(`Missing required env var: ${key}`)
    process.exit(1)
  }
})

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB error:', err))

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true }, // stores a bcrypt HASH, never plaintext
}, { timestamps: true })

const User = mongoose.model('User', userSchema)

// Usage Schema
const usageSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true },
  visits: { type: Number, default: 0 },
  paid: { type: Boolean, default: false },
}, { timestamps: true })

const Usage = mongoose.model('Usage', usageSchema)

const app = express()

// ---- Security headers ----
app.use(helmet({
  contentSecurityPolicy: false, // this is a pure API, no HTML served — CSP is a browser/frontend concern
}))

// ---- CORS locked to your actual frontend, not '*' ----
app.use(cors({
  origin: process.env.FRONTEND_ORIGIN, // e.g. 'https://coolai-five.vercel.app'
  credentials: true,
}))

app.use(express.json({ limit: '100kb' })) // cap body size to reduce DoS surface

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY })

const ADMIN_EMAILS = [
  'meghashruti2003@gmail.com',
  'admin@3rsandmconsultants.com',
  'ranjeet@3rsandmconsultants.com',
  'debashis.teri@3rsandmconsultants.com',
]

// ---- Rate limiters ----
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: 10,
  message: { error: 'Too many attempts, please try again later' },
})

const chatLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 min
  max: 15,
  message: { error: 'Too many requests, slow down' },
})

// ---- Basic validation helpers ----
const isValidEmail = (email) => typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)

// =========================================================
// Register endpoint
// =========================================================
app.post('/api/register', authLimiter, async (req, res) => {
  const { name, email, password } = req.body

  if (!name || typeof name !== 'string' || !name.trim()) {
    return res.status(400).json({ error: 'Name is required' })
  }
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Valid email is required' })
  }
  if (!password || typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' })
  }

  try {
    const existing = await User.findOne({ email: email.toLowerCase() })
    if (existing) return res.status(400).json({ error: 'Email already registered' })

    const hashedPassword = await bcrypt.hash(password, 12)
    const user = new User({ name: name.trim(), email: email.toLowerCase(), password: hashedPassword })
    await user.save()

    const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' })
    res.json({ success: true, token, user: { name: user.name, email: user.email } })
  } catch (err) {
    console.error('Register error:', err)
    res.status(500).json({ error: 'Server error' })
  }
})

// =========================================================
// Login endpoint
// =========================================================
app.post('/api/login', authLimiter, async (req, res) => {
  const { email, password } = req.body

  if (!isValidEmail(email) || !password) {
    return res.status(400).json({ error: 'Invalid email or password' })
  }

  try {
    // Only email goes into the DB query — password is compared in app code, never in the query itself.
    // This closes the NoSQL-injection login bypass from the original version.
    const user = await User.findOne({ email: email.toLowerCase() })
    if (!user) return res.status(401).json({ error: 'Invalid email or password' })

    const valid = await bcrypt.compare(password, user.password)
    if (!valid) return res.status(401).json({ error: 'Invalid email or password' })

    const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' })
    res.json({ success: true, token, user: { name: user.name, email: user.email } })
  } catch (err) {
    console.error('Login error:', err)
    res.status(500).json({ error: 'Server error' })
  }
})

// =========================================================
// User auth middleware — protects per-user routes
// =========================================================
const userAuth = (req, res, next) => {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1] // "Bearer <token>"
  if (!token) return res.status(401).json({ error: 'Unauthorized' })

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    req.user = decoded // { email }
    next()
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' })
  }
}

// Confirms the token's email matches the email the route is acting on
const ownEmailOnly = (req, res, next) => {
  const targetEmail = (req.params.email || req.body.email || '').toLowerCase()
  if (req.user.email !== targetEmail) {
    return res.status(403).json({ error: 'Forbidden' })
  }
  next()
}

// =========================================================
// Usage endpoints — now require a valid token for the SAME user
// =========================================================
app.get('/api/usage/:email', userAuth, ownEmailOnly, async (req, res) => {
  const email = req.params.email.toLowerCase()

  if (ADMIN_EMAILS.includes(email)) {
    return res.json({ visits: 0, paid: true, isAdmin: true })
  }

  try {
    const usage = await Usage.findOne({ email })
    if (!usage) return res.json({ visits: 0, paid: false })
    res.json({ visits: usage.visits, paid: usage.paid })
  } catch (err) {
    res.status(500).json({ error: 'DB error' })
  }
})

app.post('/api/usage/visit', userAuth, ownEmailOnly, async (req, res) => {
  const email = req.body.email.toLowerCase()

  if (ADMIN_EMAILS.includes(email)) {
    return res.json({ visits: 0, paid: true, isAdmin: true })
  }

  try {
    const usage = await Usage.findOneAndUpdate(
      { email },
      { $inc: { visits: 1 } },
      { upsert: true, new: true }
    )
    res.json({ visits: usage.visits, paid: usage.paid })
  } catch (err) {
    res.status(500).json({ error: 'DB error' })
  }
})

// =========================================================
// Mark user as paid
// IMPORTANT: this must NOT be reachable directly from the client in production.
// It should only be called from your payment provider's verified webhook
// (Stripe/Razorpay/etc.), which signs its payload so you can confirm it's legitimate.
// Left here as an admin-only action as a safe stopgap — wire up a real webhook
// handler separately and remove client access to this route entirely.
// =========================================================
app.post('/api/usage/pay', userAuth, ownEmailOnly, async (req, res) => {
  return res.status(403).json({
    error: 'Direct payment marking is disabled. This must go through a verified payment webhook.'
  })
})

// =========================================================
// AI chat endpoint — now requires login + rate limited
// =========================================================
app.post('/api/chat', userAuth, chatLimiter, async (req, res) => {
  const { messages, systemPrompt } = req.body

  if (!Array.isArray(messages) || messages.length === 0) {
    return res.status(400).json({ error: 'messages must be a non-empty array' })
  }

  try {
    const chatMessages = []
    if (systemPrompt && typeof systemPrompt === 'string') {
      chatMessages.push({ role: 'system', content: systemPrompt })
    }
    messages.forEach(msg => {
      chatMessages.push({
        role: msg.role === 'assistant' ? 'assistant' : 'user',
        content: String(msg.content || '').slice(0, 4000), // cap length per message
      })
    })

    const completion = await groq.chat.completions.create({
      model: 'llama-3.3-70b-versatile',
      messages: chatMessages,
      max_tokens: 1024,
    })

    const text = completion.choices[0]?.message?.content || 'No response'
    res.json({ text })
  } catch (error) {
    console.error('Groq error:', error)
    res.status(500).json({ error: 'Something went wrong' })
  }
})

// =========================================================
// Admin login — verifies credentials, issues a JWT
// =========================================================
app.post('/api/admin/login', authLimiter, async (req, res) => {
  const { username, password } = req.body
  try {
    if (username !== process.env.ADMIN_USERNAME) {
      return res.status(401).json({ error: 'Invalid credentials' })
    }
    const valid = await bcrypt.compare(password, process.env.ADMIN_PASSWORD_HASH)
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' })

    const token = jwt.sign({ role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '12h' })
    res.json({ token })
  } catch (err) {
    res.status(500).json({ error: 'Server error' })
  }
})

// Admin middleware — protect all /api/admin routes
const adminAuth = (req, res, next) => {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1] // "Bearer <token>"
  if (!token) return res.status(401).json({ error: 'Unauthorized' })

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    if (decoded.role !== 'admin') return res.status(401).json({ error: 'Unauthorized' })
    next()
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' })
  }
}

// Get all users
app.get('/api/admin/users', adminAuth, async (req, res) => {
  try {
    const users = await User.find({}, '-password').sort({ createdAt: -1 })
    const usages = await Usage.find({})
    const usageMap = {}
    usages.forEach(u => { usageMap[u.email] = u })

    const result = users.map(user => ({
      name: user.name,
      email: user.email,
      createdAt: user.createdAt,
      visits: usageMap[user.email]?.visits || 0,
      paid: usageMap[user.email]?.paid || false,
      isAdmin: ADMIN_EMAILS.includes(user.email)
    }))

    res.json(result)
  } catch (err) {
    res.status(500).json({ error: 'Server error' })
  }
})

// Grant premium access (admin-triggered, this is fine as-is since it's behind adminAuth)
app.post('/api/admin/grant', adminAuth, async (req, res) => {
  const { email } = req.body
  if (!isValidEmail(email)) return res.status(400).json({ error: 'Valid email required' })
  try {
    await Usage.findOneAndUpdate(
      { email: email.toLowerCase() },
      { $set: { paid: true } },
      { upsert: true, new: true }
    )
    res.json({ success: true })
  } catch (err) {
    res.status(500).json({ error: 'Server error' })
  }
})

// Revoke premium access
app.post('/api/admin/revoke', adminAuth, async (req, res) => {
  const { email } = req.body
  if (!isValidEmail(email)) return res.status(400).json({ error: 'Valid email required' })
  try {
    await Usage.findOneAndUpdate(
      { email: email.toLowerCase() },
      { $set: { paid: false } },
      { upsert: true, new: true }
    )
    res.json({ success: true })
  } catch (err) {
    res.status(500).json({ error: 'Server error' })
  }
})

const PORT = process.env.PORT || 3001
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})