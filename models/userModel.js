const mongoose = require('mongoose');

// * modelo
const User = mongoose.model('User', {
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  codeHash: { type: String },
  codeExpiresAt: { type: Date },
  lastCodeSendAt: { type: Date },
  codeAttempts: { type: Number, default: 0 },
  resendAttempts: { type: Number, default: 0 },
  resendWindowStart: { type: Date },
  refreshTokens: { type: [String], default: [] },
  verified: { type: Boolean, default: false },
});

// * exportando modelos
module.exports = { User };
