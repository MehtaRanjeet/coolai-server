const express = require('express')
const cors = require('cors')
const dotenv = require('dotenv')
const Groq = require('groq-sdk')
const mongoose = require('mongoose')

dotenv.config()

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB error:', err))

// Usage Schema
const usageSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  visits: { type: Number, default: 0 },
  paid: { type: Boolean, default: false },
}, { timestamps: true })

const Usage = mongoose.model('Usage', usageSchema)

const app = express()
app.use(cors({ origin: '*' }))
app.use(express.json())

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY })

// Admin emails — unlimited free access
const ADMIN_EMAILS = [
  'meghashruti2003@gmail.com',
  'admin@3rsandmconsultants.com',
]

// Check usage endpoint
app.get('/api/usage/:email', async (req, res) => {
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

// Record a visit
app.post('/api/usage/visit', async (req, res) => {
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

// Mark user as paid
app.post('/api/usage/pay', async (req, res) => {
  const email = req.body.email.toLowerCase()

  if (ADMIN_EMAILS.includes(email)) {
    return res.json({ visits: 0, paid: true, isAdmin: true })
  }

  try {
    const usage = await Usage.findOneAndUpdate(
      { email },
      { $set: { paid: true } },
      { upsert: true, new: true }
    )
    res.json({ visits: usage.visits, paid: usage.paid })
  } catch (err) {
    res.status(500).json({ error: 'DB error' })
  }
})

// AI chat endpoint
app.post('/api/chat', async (req, res) => {
  const { messages, systemPrompt } = req.body
  try {
    const chatMessages = []
    if (systemPrompt) {
      chatMessages.push({ role: 'system', content: systemPrompt })
    }
    messages.forEach(msg => {
      chatMessages.push({
        role: msg.role === 'assistant' ? 'assistant' : 'user',
        content: msg.content
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

const PORT = process.env.PORT || 3001
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})