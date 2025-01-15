import { Router } from "express";
import { register, login, logout, sendVerifyOtp, verifyEmail } from '../Controller/authController.js';
import userAuth from '../middleware/userAuth.js';

const router = Router();

router.post('/register', register);
router.post('/login', login);
router.post('/logout', logout);
router.post('/send-verify-otp', userAuth, sendVerifyOtp);
router.post('verify-account', userAuth, verifyEmail);

export default router;