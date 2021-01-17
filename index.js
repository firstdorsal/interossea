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
const sanitize = require("mongo-sanitize");
const xss = require("xss");
const QRCode = require("qrcode");
const { generateRegistrationChallenge, parseRegisterRequest, parseLoginRequest, generateLoginChallenge } = require("@webauthn/server");

const { authenticator } = require("otplib");

app.listen(process.env.PORT !== undefined ? process.env.PORT : 80);
console.log("server started");
if (process.env.DEVELOPMENT) db.get("login").drop();
const webSchema = process.env.WEB_SCHEMA != undefined ? process.env.WEB_SCHEMA : "https";
console.log("debug mode set to " + !!process.env.DEBUG);
const D = process.env.DEBUG;

app.post("/akkount/v1/login", async (req, res) => {
    if (
        !req.query ||
        !req.query.email ||
        !req.query.email.match(
            /^(([^<>()\[\]\\.,;:\s@"]{1,64}(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".{1,62}"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]{1,63}\.)+[a-zA-Z]{2,63}))$/
        )
    ) {
        return res.send({ message: `error`, error: true });
    }
    const email = sanitize(xss(req.query.email));
    const redirect = sanitize(xss(req.query.from));

    const a = await db.get("login").findOne({
        email
    });
    const token = generateToken(100);
    const preSessionId = generateToken(100);
    const link = `${webSchema}://${process.env.WEB_URI}/akkount/v1/createsession?t=${token}`;
    if (a) {
        if (a.time + 1000 * 60 * process.env.SLOWDOWN > Date.now()) {
            const wait = (a.time + 1000 * 60 * process.env.SLOWDOWN - Date.now()) / 1000;
            return res.send({
                message: `Please wait another ${wait}s before requesting a new login mail`,
                error: true
            });
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
            if (error) return res.send({ message: "Invalid email", error: true });

            res.cookie("preSessionId", preSessionId, {
                maxAge: 10000000,
                path: "/",
                httpOnly: true,
                secure: true,
                sameSite: "Strict"
            });
            return res.send({ message: "Success", error: false });
        }
    );
});

app.get("/akkount/v1/createsession", async (req, res) => {
    // send error if token is missing
    if (!req.query) return res.send({ message: "no query specified", error: true });

    if (!req.query.t) return res.send({ message: "no login token present", error: true });

    //sanitize the token
    req.query.t = sanitize(xss(req.query.t));

    //find corresponding email for token
    const a = await db.get("login").findOne({
        token: req.query.t
    });
    //delete login
    await db.get("login").findOneAndDelete({
        token: req.query.t
    });
    //check if token exists and hasnt expired
    if (!a) return res.send({ message: "Invalid login token", error: true });

    if (!a.time || a.time + 1000 * 60 * process.env.SLOWDOWN < Date.now()) {
        return res.send({ message: "Expired login token", error: true });
    }
    //check if ip requesting the token is the same as ip trying to start a session with it
    if (!a.ip || a.ip !== req.headers["x-forwarded-for"]) {
        return res.send({ message: "Request was sent from a different IP", error: true });
    }
    if (!req.cookies) return res.send({ message: "missing cookies", error: true });

    if (!req.cookies.preSessionId) return res.send({ message: "missing preSessionId cookie", error: true });

    const preSessionId = sanitize(xss(req.cookies.preSessionId));

    //check if browser origin and device is the same
    if (!a.preSessionId || a.preSessionId !== preSessionId) {
        return res.send({ message: "invalid preSessionId cookie: Request was sent from a different origin/browser", error: true });
    }

    //try to find user with email
    let user = await db.get("user").findOne({
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
        user = { userId };
    } else if (user.totpActive || user.webAuthnActive) {
        //check if 2fa is present

        const firstFactorToken = generateToken(100);
        if (D) console.log("/akkount/v1/createsession", firstFactorToken);

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

        if (user.totpActive && user.webAuthnActive) return res.redirect("/login/2fa");
        if (user.totpActive) return res.redirect("/login/2fa/totp");
        return res.redirect("/login/2fa/webauthn");
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
    return res.redirect("/2fa");
});

app.post("/akkount/v1/2fa/totp/generate", async (req, res) => {
    const a = await checkSession(req);
    if (!a) return res.send({ message: "invalid session", error: true });
    if (a.totpActive) {
        if (!req.query || !req.query.replace || req.query.replace !== "true") {
            return res.send({ message: "totp already activated; send the query replace=true to override", error: true, warning: "token is present" });
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

app.post("/akkount/v1/2fa/totp/register", async (req, res) => {
    const a = await checkSession(req);
    if (!a) return res.send({ message: "invalid session token", error: true });
    if (!req.query) return res.send({ message: "no query specified", error: true });
    if (!req.query.totp) return res.send({ message: "totp token missing", error: true });
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
        return res.send({ message: "correct totp token", error: false });
    }
    return res.send({ message: "invalid totp token", error: true });
});

app.post("/akkount/v1/2fa/webauthn/register/request", async (req, res) => {
    const user = await checkSession(req);
    if (!user) return res.send({ message: "invalid session token", error: true });

    const challengeResponse = generateRegistrationChallenge({
        relyingParty: { name: process.env.DISPLAY_NAME },
        user: { id: user.userId, name: user.userId }
    });

    db.collection("user").findOneAndUpdate(
        {
            _id: user._id
        },
        {
            $set: {
                webAuthnRegisterChallenge: challengeResponse.challenge
            }
        }
    );

    return res.send(challengeResponse);
});

app.post("/akkount/v1/2fa/webauthn/register/verify", async (req, res) => {
    const user = await checkSession(req);
    if (!user) return res.send({ message: "invalid session token", error: true });

    const { key, challenge } = parseRegisterRequest(req.body);
    db.collection("user").findOne({ webAuthnRegisterChallenge: challenge });

    if (db.collection.length) {
        db.collection("user").findOneAndUpdate(
            {
                _id: user._id
            },
            {
                $set: {
                    webAuthnKey: key,
                    webAuthnActive: true
                }
            }
        );
        return res.send({ message: "Success", error: false });
    }
    return res.send({ message: "WebAuthn challenge failed", error: true });
});

app.post("/akkount/v1/createsession/2fa/totp", async (req, res) => {
    if (!req.cookies) return res.send({ message: "missing cookies", error: true });
    if (!req.cookies.firstFactorToken) return res.send({ message: "missing firstFactorToken cookie", error: true });
    if (!req.query) return res.send({ message: "missing query", error: true });
    if (!req.query.totp) return res.send({ message: "missing totp query", error: true });

    const login = await db.get("login").findOne({ firstFactorToken: req.cookies.firstFactorToken });
    if (!login) return res.send({ message: "invalid firstFactorToken", error: true });

    const user = await db.get("user").findOne({ userId: login.userId });
    if (authenticator.generate(user.totpSecret) === req.query.totp) {
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
        if (login.redirect !== "undefined") return res.redirect("/" + login.redirect);
        return res.redirect("/");
    }
    return res.send({ message: "invalid totp", error: true });
});

app.post("/akkount/v1/createsession/2fa/webauthn/request", async (req, res) => {
    if (!req.cookies) return res.send({ message: "missing cookies", error: true });
    if (!req.cookies.firstFactorToken) return res.send({ message: "missing firstFactorToken cookie", error: true });
    const fft = sanitize(xss(req.cookies.firstFactorToken));

    const login = await db.get("login").findOne({ firstFactorToken: fft });

    if (!login) return res.send({ message: "invalid firstFactorToken", error: true });
    const user = await db.get("user").findOne({ userId: login.userId });
    if (!user) return res.send({ message: "user not found", error: true });
    if (!user.key) return res.send({ message: "missing public key for this user", error: true });

    const newChallenge = generateLoginChallenge(user.key);
    db.collection("login").findOneAndUpdate(
        {
            _id: login._id
        },
        {
            $set: {
                webAuthnLoginChallenge: newChallenge
            }
        }
    );
    res.send(newChallenge);
});
app.post("/akkount/v1/createsession/2fa/webauthn/verify", async (req, res) => {
    if (!req.cookies) return res.send({ message: "missing cookies", error: true });
    if (!req.cookies.firstFactorToken) return res.send({ message: "missing firstFactorToken cookie", error: true });
    if (!req.body) return res.send({ message: "missing body", error: true });
    const login = await db.get("login").findOne({ firstFactorToken: req.cookies.firstFactorToken });
    if (!login) return res.send({ message: "invalid firstFactorToken", error: true });

    const solvedChallenge = parseLoginRequest(req.body);
    if (solvedChallenge === login.webAuthnLoginChallenge) {
        const user = await db.get("user").findOne({ userId: login.userId });

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
        if (login.redirect !== "undefined") return res.redirect("/" + login.redirect);
        return res.redirect("/");
    }
    return res.send({ message: "WebAuthn challenge failed", error: true });
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
    return cryptoRandomString({ length, characters: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-" });
};
