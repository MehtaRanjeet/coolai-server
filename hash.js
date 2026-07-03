// hash.js — run once with: node hash.js
const bcrypt = require('bcryptjs')
const password = 'CoolAI_user@1234'
bcrypt.hash(password, 10).then(hash => console.log(hash))