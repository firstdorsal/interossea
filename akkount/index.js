"use strict";
require(`dotenv`).config()
const express = require('express');
const app = express();
const nodemailer = require("nodemailer");
const db = require('monk')(process.env.DB, {
    useUnifiedTopology: true
});
const crypto = require('crypto');

app.listen(process.env.PORT ? process.env.PORT : 80);
console.log('server started');

app.post('/login', async (req, res) => {
    if (!req.query || !req.query.email) {
        res.send('Error');
        return;
    }

    const a = await db.get('login').findOne({
        email: req.query.email
    });

    const token = generateToken(100);
    const link = `https://${process.env.WEB_URI}/verify?t=${token}`;
    if (a) {
        if (a.time + 1000 * 60 * 3 > Date.now()) {
            const wait = (a.time + 1000 * 60 * 3 - Date.now()) / 1000;
            res.send({
                message: `Please wait another ${wait}s before requesting a new login mail.`,
                seconds: wait
            });
            return;
        }
        await db.get('login').findOneAndUpdate({
            email: req.query.email
        }, {
            $set: {
                time: Date.now(),
                token
            }
        });
    } else {
        await db.get('login').insert({
            email: req.query.email,
            time: Date.now(),
            token
        });
    }





    const transporter = nodemailer.createTransport({
        host: process.env.MAIL_HOST,
        port: 465,
        secure: true,
        tls: {
            rejectUnauthorized: true
        },
        auth: {
            user: process.env.LOGIN_MAIL_USERNAME,
            pass: process.env.LOGIN_MAIL_PASSWORD
        }
    });

    transporter.sendMail({
        headers: {
            "User-Agent": process.env.MAIL_AGENT,
            "X-Mailer": process.env.MAIL_AGENT
        },
        from: `"${process.env.FROM_NAME}" <${process.env.LOGIN_MAIL_USERNAME}>`,
        to: req.query.email,
        subject: process.env.FROM_NAME,
        text: `${link}`,
        html: `${link}`
    }, (error, info) => {
        if (error) {
            console.log(error);
            res.send('Invalid email');
        } else {
            res.send('OK');
        }
    });
});

app.get('/verify', async (req, res) => {

});

function generateToken(length) {
    return crypto.randomBytes(length).toString('base64').replace(/\//g, '_').replace(/\+/g, '-').replace(/\=/g, '')
}