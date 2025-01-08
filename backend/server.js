import cors from 'cors';
import express from 'express';
import mongoose from 'mongoose';
import { configDotenv } from 'dotenv';
import authRoutes from './Routes/authRoutes.js';

configDotenv();
const app = express();
const port = process.env.PORT || 4000;

app.use(express.json());
app.use(cors({ credentials: true }));

app.get('/', (req, res, next) => {
    res.json({ mssg: 'Hello Node' });
    next();
});

app.use('/api/auth', authRoutes);

mongoose.connect(process.env.MONGO_URL)
    .then(() => {
        console.log('DB connected successfully');
        app.listen(port, () => {
            console.log(`We are listening at port number ${ port }.....`);
        });
    })
    .catch(err => console.log(err.message));
