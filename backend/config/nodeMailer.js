import nodemailer from 'nodemailer';

const transporter = nodemailer.createTransport({
    host: 'smtp.ethereal.email',
    port: 587,
    auth: {
        user: 'joyce42@ethereal.email',
        pass: 'XAJhrF2zJrUmaScm7N'
    }
});

export default transporter;