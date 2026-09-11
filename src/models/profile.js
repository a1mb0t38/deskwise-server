const mongoose = require('mongoose');

const profileSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
        unique: true,
    },
    role: {
        type: String,
        enum: ['user', 'agent', 'admin'],
        default: 'user',
    },
    department: {
        type: String,
        required: false,
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
});

const Profile = mongoose.model('Profile', profileSchema);

module.exports = Profile;