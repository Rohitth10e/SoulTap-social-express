require('dotenv').config(); // Load environment variables
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI)
    .then(() => { console.log("connected to db") })
    .catch((err) => { console.log("Could not connect to db: ", err.message) });

// User Schema Definition
const userSchema = mongoose.Schema({
    name: { type: String, required: true },
    username: { type: String, required: true, unique: true },
    age: { type: Number, min: 0 },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    profilePicture: {
        type: String,
        default: "default.png"
    },
    posts: [{ type: mongoose.Types.ObjectId, ref: "Post" }]
});

// Password hashing before saving
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
});

// Create and export the User model
module.exports = mongoose.model('User', userSchema);
