import 'dotenv/config';
import express from 'express';
import cors from 'cors';

const app = express();
app.use(cors({
    origin: process.env.FRONTEND_URL,
    credentials: true
}));

const PORT = process.env.PORT || 5000;

app.get('/', (req, res) => {
    res.send("server is running");
})

app.listen(PORT, ()=>{
    console.log(`Server is running on port ${PORT}`);
})