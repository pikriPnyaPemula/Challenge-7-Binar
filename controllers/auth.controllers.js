const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const {JWT_SECRET_KEY} = process.env;
const nodemailer = require('../utils/nodemailer')

module.exports = {
    register: async (req, res, next) => {
        try {
            let {name, email, password, password_confirmation} = req.body;
            if(password != password_confirmation) {
                return res.status(400).json({
                    status: false,
                    message: 'Bad Request',
                    err: 'Please ensure the password and password confirmation match!',
                    data: null
                });

            };

            let userExist = await prisma.user.findUnique({where: {email}});
            if(userExist) {
                return res.status(400).json({
                    status: false,
                    message: 'Bad Request',
                    err:  'User has been already used!',
                    data: null
                });
            }

            let encryptedPassword = await bcrypt.hash(password, 10);
            let user = await prisma.user.create({
                data: {
                    name,
                    email,
                    password: encryptedPassword
                }
            });

            // kirim email
            // let token = jwt.sign({email : user.email}, JWT_SECRET_KEY);
            // let url = `http://localhost:3000/api/v1/auth/email-activation?token=${token}`;

            // const html = await nodemailer.getHtml('activation-email.ejs', {name, url});
            // nodemailer.sendEmail(email, 'Email Activation', html);

            return res.status(201).json({
                status: true,
                message: 'Created!',
                err: null,
                data: {user}
            });
        } catch (err) {
            next(err);
        }
    },

    login: async (req, res, next)=> {
        try {
            let {email, password} = req.body;

            let user = await prisma.user.findUnique({where: {email}});
            if(!user) {
                return res.status(400).json({
                    status: false,
                    message: 'Bad Request',
                    err:  'invalid email or password',
                    data: null
                });
            }

            let isPasswordCorrect = await bcrypt.compare(password, user.password);
            if (!isPasswordCorrect) {
                return res.status(400).json({
                    status: false,
                    message: 'Bad Request',
                    err: 'invalid email or password!',
                    data: null
                });
            }

            let token = jwt.sign({id: user.id}, JWT_SECRET_KEY);
            return res.status(200).json({
                status: true,
                message: 'OK',
                err: null,
                data: {user, token}
            });

        }catch(err){
            next(err);
        }
    },

    whoAmI: (req, res, next) => {
        return res.status(200).json({
            status: true,
            message: 'OK',
            err: null,
            data: {user: req.user}
        });
    },

    forgetPassword: async (req, res, next) => {
        try {
            const { email } = req.body;
    
            const user = await prisma.user.findUnique({ where: { email } });
            if (!user) {
                return res.status(400).json({
                    status: false,
                    message: 'Bad Request',
                    err: 'User not found',
                    data: null
                });
            }
    
            const resetToken = jwt.sign({ email: user.email }, JWT_SECRET_KEY, { expiresIn: '1h' });
            const resetLink = `http://localhost:3000/reset-password?token=${resetToken}`;
    
            // Log token dan hasil decode token
            console.log('Reset Token:', resetToken);
    
            const html = await nodemailer.getHtml('reset-password.ejs', { name: user.name, resetLink });
            nodemailer.sendEmail(email, 'Reset Password', html);
    
            return res.status(200).json({
                status: true,
                message: 'OK',
                err: null,
                data: { message: 'Password reset link has been sent to your email.' }
            });
        } catch (err) {
            console.error('Error in forgetPassword:', err);
            next(err);
        }
    },

    resetPassword: async (req, res, next) => {
        try {
            const { token } = req.query;

            // Log token untuk memeriksa apakah nilainya diambil dengan benar
            console.log('Reset Token:', token);

            // Logika untuk mereset password

            return res.status(200).json({
                status: true,
                message: 'OK',
                err: null,
                data: { message: 'Password reset successful.' }
            });
        } catch (err) {
            console.error('Error in resetPassword:', err);
            next(err);
        }
    }
    
};