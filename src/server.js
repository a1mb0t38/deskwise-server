import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';
import profileRoutes from './routes/profile.js';
import { toNodeHandler } from 'better-auth/node';
import { auth } from './auth.js'; 


const app = express();
app.use(cors({
    origin: process.env.FRONTEND_URL,
    credentials: true
}));

app.all('/api/auth/*splat', toNodeHandler(auth));

app.use(express.json());


app.use("/api/profile", profileRoutes);

const PORT = process.env.PORT || 5000;

app.get('/', (req, res) => {
    res.send("server is running");
})

async function startServer(){
    try{
        await mongoose.connect(process.env.MONGODB_URI);
        console.log("Connected to MongoDB");
        app.listen(PORT, ()=>{
            console.log(`Server is running on port ${PORT}`);
        })

    }catch(err){
        console.error("Faild to connect to MongoDB", err.message)
        process.exit(1);
    }
}

startServer();