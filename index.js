"use strict";
require(`dotenv`).config();
const express = require("express");
const cookieParser = require("cookie-parser");
const compression = require("compression");
const cors = require("cors");
const bodyParser = require("body-parser");
const cryptoRandomString = require("crypto-random-string");

const app = express();
app.use(cookieParser());
app.use(compression());
app.use(cors());
app.use(bodyParser.json());

const nodemailer = require("nodemailer");
const db = require("monk")(process.env.DB_URI, {
    useUnifiedTopology: true
});
const crypto = require("crypto");
const sanitize = require("mongo-sanitize");
const xss = require("xss");
const QRCode = require("qrcode");
const { generateRegistrationChallenge, parseRegisterRequest } = require("@webauthn/server");

const { authenticator } = require("otplib");

app.listen(process.env.PORT != undefined ? process.env.PORT : 80);
console.log("server started");
db.get("login").drop();
const webSchema = process.env.WEB_SCHEMA != undefined ? process.env.WEB_SCHEMA : "https";

app.post("/akkount/login", async (req, res) => {
    if (
        !req.query ||
        !req.query.email ||
        !req.query.email.match(
            /^(([^<>()\[\]\\.,;:\s@"]{1,64}(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".{1,62}"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]{1,63}\.)+[a-zA-Z]{2,63}))$/
        )
    ) {
        res.send({ message: `error`, error: true });
        return;
    }
    const email = sanitize(xss(req.query.email));
    const redirect = sanitize(xss(req.query.from));

    const a = await db.get("login").findOne({
        email
    });
    const token = generateToken(100);
    const preSessionId = generateToken(100);
    const link = `${webSchema}://${process.env.WEB_URI}/akkount/createsession?t=${token}`;
    if (a) {
        if (a.time + 1000 * 60 * process.env.SLOWDOWN > Date.now()) {
            const wait = (a.time + 1000 * 60 * process.env.SLOWDOWN - Date.now()) / 1000;
            res.send({
                message: `Please wait another ${wait}s before requesting a new login mail`,
                error: true
            });
            return;
        }
        db.get("login").findOneAndUpdate(
            {
                email
            },
            {
                $set: {
                    time: Date.now(),
                    token,
                    ip: req.headers["x-forwarded-for"],
                    preSessionId,
                    redirect
                }
            }
        );
    } else {
        db.get("login").insert({
            email,
            time: Date.now(),
            token,
            ip: req.headers["x-forwarded-for"],
            preSessionId,
            redirect
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

    transporter.sendMail(
        {
            headers: {
                "User-Agent": process.env.MAIL_AGENT,
                "X-Mailer": process.env.MAIL_AGENT,
                "Reply-To": process.env.REPLY_TO
            },
            from: `"${process.env.FROM_NAME}" <${process.env.FROM_MAIL_ADDRESS}>`,
            to: req.query.email,
            subject: process.env.FROM_NAME,
            text: `Someone requested a link to log into your account. If this was you: Open this link in your browser ${link} Never share this link with anyone!`,
            html: `Someone requested a link to log into your account. If this was you: Click on the link to <a href="${link}"><b>Login</b></a> <p style="color:red;"> <b>Never share this link with anyone!</b></p>`
        },
        (error, info) => {
            if (error) {
                console.log(error);
                res.send({ message: "Invalid email", error: true });
            } else {
                res.cookie("preSessionId", preSessionId, {
                    maxAge: 10000000,
                    path: "/",
                    httpOnly: true,
                    secure: true,
                    sameSite: "Strict"
                });
                res.send({ message: "Success", error: false });
            }
        }
    );
});

app.get("/akkount/createsession", async (req, res) => {
    // send error if token is missing
    if (!req.query) {
        res.send({ message: "no query specified", error: true });
        return;
    }
    if (!req.query.t) {
        res.send({ message: "no token present", error: true });
        return;
    }

    //sanitize the token
    req.query.t = sanitize(xss(req.query.t));

    //find corresponding email for token
    const a = await db.get("login").findOne({
        token: req.query.t
    });
    //delete token
    await db.get("login").findOneAndUpdate(
        {
            token: req.query.t
        },
        {
            $set: {
                token: ""
            }
        }
    );
    //check if token exists and hasnt expired
    if (!a) {
        res.send({ message: "Invalid token", error: true });
        return;
    }
    if (!a.time || a.time + 1000 * 60 * process.env.SLOWDOWN < Date.now()) {
        res.send({ message: "Expired token", error: true });
        return;
    }
    //check if ip requesting the token is the same as ip trying to start a session with it
    if (!a.ip || a.ip !== req.headers["x-forwarded-for"]) {
        res.send({ message: "Request was sent from a different IP", error: true });
        return;
    }
    if (!req.cookies) {
        res.send({ message: "missing cookies", error: true });
        return;
    }
    if (!req.cookies.preSessionId) {
        res.send({ message: "missing preSessionId cookie", error: true });
        return;
    }
    const preSessionId = sanitize(xss(req.cookies.preSessionId));

    //check if browser origin and device is the same
    if (!a.preSessionId || a.preSessionId !== preSessionId) {
        res.send({ message: "invalid preSessionId cookie: Request was sent from a different origin/browser", error: true });
        return;
    }

    //try to find user with email
    const user = await db.get("user").findOne({
        email: a.email
    });

    const firstTime = !user;

    //create new user if dont exist
    if (!user) {
        const userId = "u" + generateToken(14);

        await db.get("user").insert({
            userId,
            email: a.email,
            time: Date.now(),
            ip: req.headers["x-forwarded-for"]
        });
        user = {
            userId
        };
    } else if (user.totpActive) {
        //check if 2fa is present

        const firstFactorToken = generateToken(100);
        //add firstFactorToken to db
        await db.get("login").insert({
            firstFactorToken,
            userId: user.userId,
            time: Date.now(),
            ip: req.headers["x-forwarded-for"],
            userAgent: req.headers["user-agent"] ? req.headers["user-agent"] : ""
        });
        //append firstFactorToken cookie to response
        res.cookie("firstFactorToken", firstFactorToken, {
            maxAge: 10000000,
            path: "/",
            httpOnly: true,
            secure: true,
            sameSite: "Strict"
        });
        if (user.totpActive) {
            res.redirect("/2fa/totp");
            return;
        }
    }
    //generate session id
    const newSessionID = generateToken(100);

    //save session cookie to db
    await db.get("session").insert({
        session: newSessionID,
        userId: user.userId,
        time: Date.now(),
        ip: req.headers["x-forwarded-for"],
        userAgent: req.headers["user-agent"] ? req.headers["user-agent"] : ""
    });

    //append session cookie to response
    res.cookie("session", newSessionID, {
        maxAge: 10000000000,
        path: "/",
        httpOnly: true,
        secure: true,
        sameSite: "Strict"
    });

    //if redirect was specified at login redirect to location
    if (firstTime) {
        res.redirect("/profile");
        return;
    } else if (a.redirect !== "undefined") {
        res.redirect("/" + a.redirect);
        return;
    }
    res.redirect("/");
});

app.post("/akkount/2fa/totp/generate", async (req, res) => {
    const a = await checkSession(req);
    if (!a) {
        res.send({ message: "invalid session", error: true });
        return;
    }
    if (a.totpActive) {
        if (!req.query || !req.query.replace || req.query.replace !== "true") {
            res.send({ message: "totp already activated; send the query replace=true to override", error: true, warning: "token is present" });
            return;
        }
    }
    const secret = authenticator.generateSecret();
    const otpauth = authenticator.keyuri(a.userId, process.env.WEB_URI, secret);
    db.collection("user").findOneAndUpdate(
        {
            _id: a._id
        },
        {
            $set: {
                totpSecret: secret
            }
        }
    );

    QRCode.toDataURL(otpauth, (err, url) => {
        res.status(200).send({
            qrCode: url,
            secret
        });
    });
});

app.post("/akkount/2fa/totp/register", async (req, res) => {
    const a = await checkSession(req);

    if (!a) {
        res.send({ message: "invalid session", error: true });
        return;
    }

    if (!req.query) {
        res.send({ message: "no query specified", error: true });
        return;
    }

    if (!req.query.totp) {
        res.send({ message: "totp token missing", error: true });
        return;
    }

    if (authenticator.generate(a.totpSecret) === req.query.totp) {
        await db.collection("user").findOneAndUpdate(
            {
                _id: a._id
            },
            {
                $set: {
                    totpActive: true
                }
            }
        );
        res.send({ message: "correct token", error: false });
    } else {
        res.send({ message: "invalid totp token", error: true });
    }
});

app.post("/akkount/2fa/webauthn/register/request", async (req, res) => {
    const a = await checkSession(req);
    if (!a) {
        res.send({ message: "invalid session", error: true });
        return;
    }
    const challengeResponse = generateRegistrationChallenge({
        relyingParty: { name: process.env.DISPLAY_NAME },
        user: { id: a.userId, name: a.userId }
    });

    db.collection("user").findOneAndUpdate(
        {
            _id: a._id
        },
        {
            $set: {
                webAuthnRegisterChallenge: challengeResponse.challenge
            }
        }
    );

    res.send(challengeResponse);
});

app.post("/akkount/2fa/webauthn/register/verify", async (req, res) => {
    const a = await checkSession(req);
    if (!a) {
        return res.send({ message: "invalid session", error: true });
    }

    const { key, challenge } = parseRegisterRequest(req.body);
    db.collection("user").findOne({ webAuthnRegisterChallenge: challenge });

    if (db.collection.length) {
        db.collection("user").findOneAndUpdate(
            {
                _id: a._id
            },
            {
                $set: {
                    webAuthnKey: key
                }
            }
        );

        return res.send({ message: "Success", error: false });
    }
});

app.get("*", (req, res) => {
    res.sendStatus(404);
});
app.post("*", (req, res) => {
    res.sendStatus(404);
});

const checkSession = async req => {
    const sessionCookie = sanitize(xss(req.cookies.session));
    const session = await db.get("session").findOne({
        session: sessionCookie
    });
    if (!session) return false;
    const user = await db.get("user").findOne({
        userId: session.userId
    });
    if (!user) return false;
    return user;
};

const generateToken = length => {
    return cryptoRandomString({ length, type: "base64" });
};
