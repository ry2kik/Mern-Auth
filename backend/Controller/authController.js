import jwt from 'jsonwebtoken';
import bcryptjs from 'bcryptjs';
import validator from 'validator';
import userModel from "../Model/userModel.js";

// TODO Creating Token for the user
function createToken(id) {
    return jwt.sign({ id }, process.env.SECRET, { expiresIn: '7d' });
}


// TODO Sign-up User
export const register = async (req, res) => {
    const { name, email, password } = req.body;

    // TODO Checking all the fields are filled or not 
    if (!name || !email || !password) {
        return res.status(400).json({ success: false, mssg: 'All the details are missing' });
    }


    // TODO Checking if the user enter a valid email or not
    if (!validator.isEmail(email)) {
        return res.status(400).json({ success: false, mssg: 'Please enter a valid email' });
    }


    // TODO Checking if the user enter a strong password or not
    if (!validator.isStrongPassword(password)) {
        return res.status(400).json({ success: false, mssg: 'Please enter a strong password' });
    }

    try {
        // TODO Checking if the email already exists or not
        const exists = await userModel.findOne({ email });
        if (exists) {
            return res.json({ success: false, mssg: 'User already exist' });
        }


        // TODO Creating an new user with an encrypted password
        const saltPassword = await bcryptjs.genSalt(10);
        const hashPassword = await bcryptjs.hash(password, saltPassword);
        const user = new userModel({ name, email, password: hashPassword });
        await user.save();


        // TODO Creating a token and cookie for the newly created user
        const token = createToken(user._id);
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        return res.status(200).json({ success: true, mssg: 'New User created successfully', user });
    } catch(error) {
        return res.status(400).json({ success: false, mssg: error.message });
    }
}


// TODO Login User
export const login = async (req, res) => {
    const { email, password } = req.body;


    // TODO Checking all the fields are filled or not 
    if (!email || !password) {
        return res.status(400).json({ success: false, mssg: 'All the details are missing' });
    }

    try {
        // TODO Checking if the email already exists or not
        const user = await userModel.findOne({ email });
        if (!user) {
            return res.status(400).json({ success: false, mssg: "Invalid Email address." });
        }

        // TODO Comparing the two passwords
        const isMatch = await bcryptjs.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ success: false, mssg: 'Invalid Password' });
        }

        // TODO Creating a token and cookie for the newly created user
        const token = createToken(user._id);
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        return res.status(200).json({ success: true, mssg: 'User logged in successfully' });
    } catch(error) {
        return res.status(400).json({ success: false, mssg: error.message });
    }
}

// TODO Logout user
export const logout = async (req, res) => {
    try {
        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict'
        });

        return res.status(200).json({ success: true, mssg: 'Logged out successfully' });
    } catch (error) {
        return res.status(200).json({ success: false, mssg: error.message });
    }
}