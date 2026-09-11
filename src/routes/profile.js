const express = require('express');
const Profile = require('../models/profile');
const {requireAuth} = require('../middleware/requireAuth');

const router = express.Router();

router.post("/complete", requireAuth, async (req, res) => {
    try{
        const userId = req.user.id;
        const {role, department} = req.body;

        const existing = await Profile.findOne({userId});
        if(existing){
            return res.status(409).json({message: "Profile already exists"});
        }

        const profile = new Profile({
            userId,
            role,
            department
        });

        res.status(201).json(profile);
    }catch(err){
        console.error("Profile creation Error", err.message);
        res.status(500).json({message: "intternal server error"});
    }
})

module.exports = router;