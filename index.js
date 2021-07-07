`use strict`;
require(`dotenv`).config();
const express = require(`express`);
const cookieParser = require(`cookie-parser`);
const compression = require(`compression`);
const bodyParser = require(`body-parser`);
const cryptoRandomString = require(`crypto-random-string`);
const helmet = require(`helmet`);
const rateLimit = require(`express-rate-limit`);
const path = require(`path`);

const app = express();

const nodemailer = require(`nodemailer`);

const DB_URI = process.env.DB_URI !== undefined ? process.env.DB_URI : `db`;

const db = require(`monk`)(DB_URI, {
    useUnifiedTopology: true
});

const sanitize = require(`mongo-sanitize`);
const xss = require(`xss`);
const qrcode = require(`qrcode`);
const { generateRegistrationChallenge, parseRegisterRequest, parseLoginRequest, generateLoginChallenge, verifyAuthenticatorAssertion } = require(`@webauthn/server`);
const { authenticator } = require(`otplib`);

// define and handle global variables
const WEBSCHEMA = process.env.WEB_SCHEMA != undefined ? process.env.WEB_SCHEMA : `https`;
const PORT = process.env.PORT !== undefined ? process.env.PORT : 80;
const WEB_URL = process.env.WEB_URL != undefined ? process.env.WEB_URL : `localhost`;
console.log(`server started on port ${WEBSCHEMA}://${WEB_URL}:${PORT}`);

const DEBUG = process.env.DEBUG !== undefined ? process.env.DEBUG : false;
console.log(`debug mode set to ${DEBUG}. ${DEBUG ? `DONT USE IN PRODUCTION` : ``}`);
const SECURE_COOKIE_ATTRIBUTES = { path: `/`, httpOnly: true, secure: true, sameSite: `Strict` };
const BASE_URL = `/interossea`;

const REQUEST_NEW_MAGIC_LINK_MINUTES = process.env.REQUEST_NEW_MAGIC_LINK_MINUTES !== undefined ? process.env.REQUEST_NEW_MAGIC_LINK_MINUTES : 0.5;

const MAGIC_LINK_EXPIRE_MINUTES = process.env.MAGIC_LINK_EXPIRE_MINUTES !== undefined ? process.env.MAGIC_LINK_EXPIRE_MINUTES : 10;

const IP_REQUEST_TIME_MINUTES = process.env.IP_REQUEST_TIME_MINUTES !== undefined ? process.env.IP_REQUEST_TIME_MINUTES : 10;

const IP_REQUEST_PER_TIME = process.env.IP_REQUEST_PER_TIME !== undefined ? process.env.IP_REQUEST_PER_TIME : 100;

// set express settings
const server = app.listen(PORT);
app.use(cookieParser());
app.use(compression());
app.use(bodyParser.json({ limit: `10kb` }));
app.use(helmet.hidePoweredBy());
app.disable(`etag`);
app.use(express.static(`public`));
app.set(`view engine`, `pug`);
app.locals.basedir = path.join(__dirname, `views`);

// apply rate limiting to login
const limiter = rateLimit({
    windowMs: IP_REQUEST_TIME_MINUTES * 60 * 1000,
    max: IP_REQUEST_PER_TIME
});
app.use(`${BASE_URL}/v1/login`, limiter);

// frontend
app.get(`${BASE_URL}/`, (req, res) => {
    res.render(`index`);
});
if (!process.env.DISABLE_FRONTEND) {
    app.get(`${BASE_URL}/login`, (req, res) => {
        res.render(`login/index`);
    });
}

// TODO ADD JWT AS COOKIE THAT PROOFS THAT USER HAS SIGNED IN BEFORE

// handle clicked link
app.get(`${BASE_URL}/v1/createsession`, async (req, res) => {
    res.cookie(`session`, ``, {
        maxAge: 1,
        ...SECURE_COOKIE_ATTRIBUTES
    });
    res.cookie(`preSessionId`, ``, {
        maxAge: 1,
        ...SECURE_COOKIE_ATTRIBUTES
    });

    // send error if token is missing
    if (!req.query) return errorWebResponse(res, { message: `no query specified`, error: true });

    if (!req.query.t) return errorWebResponse(res, { message: `no login token present`, error: true });

    // sanitize the token
    const t = sanitize(xss(req.query.t));

    // find corresponding email for token
    const a = await db.get(`login`).findOne({
        token: t
    });
    // delete login
    await db.get(`login`).findOneAndDelete({
        token: t
    });
    // check if token exists and hasnt expired
    if (!a) return errorWebResponse(res, { message: `Invalid login token`, error: true }, true);

    if (!a.time || a.time + 1000 * 60 * MAGIC_LINK_EXPIRE_MINUTES < Date.now()) {
        return errorWebResponse(res, { message: `Expired login token`, error: true }, true);
    }
    // check if ip requesting the token is the same as ip trying to start a session with it
    if (!DEBUG) {
        if (!a.ip || a.ip !== req.headers[`x-forwarded-for`]) {
            return errorWebResponse(res, { message: `Request was sent from a different IP`, error: true }, true);
        }
    }
    if (!req.cookies) return errorWebResponse(res, { message: `missing cookies`, error: true });

    if (!req.cookies.preSessionId) return errorWebResponse(res, { message: `missing preSessionId cookie: Request was sent from a different origin/browser`, error: true }, true);

    const preSessionId = sanitize(xss(req.cookies.preSessionId));

    // check if browser origin and device is the same
    if (!a.preSessionId || a.preSessionId !== preSessionId) {
        return errorWebResponse(res, { message: `invalid preSessionId cookie: Request was sent from a different origin/browser`, error: true }, true);
    }

    // try to find user with email
    let user = await db.get(`user`).findOne({
        email: a.email
    });

    // create new user if dont exist
    if (!user) {
        const userId = `u` + generateToken(14);

        await db.get(`user`).insert({
            userId,
            email: a.email,
            time: Date.now(),
            ip: req.headers[`x-forwarded-for`]
        });
        user = { userId };
    } else if (user.totpActive || user.webAuthnActive) {
        // check if 2fa is present

        const firstFactorToken = generateToken(100);

        // add firstFactorToken to db
        await db.get(`login`).insert({
            firstFactorToken,
            userId: user.userId,
            time: Date.now(),
            ip: req.headers[`x-forwarded-for`],
            userAgent: req.headers[`user-agent`] ? req.headers[`user-agent`] : ``
        });

        // append firstFactorToken cookie to response
        res.cookie(`firstFactorToken`, firstFactorToken, {
            maxAge: 10000000,
            ...SECURE_COOKIE_ATTRIBUTES
        });

        if (user.totpActive && user.webAuthnActive) return res.redirect(`/login/2fa`);
        if (user.totpActive) return res.redirect(`/login/2fa/totp`);
        return res.redirect(`/login/2fa/webauthn`);
    }
    // generate session id
    const newSessionID = generateToken(100);

    // save session cookie to db
    await db.get(`session`).insert({
        session: newSessionID,
        userId: user.userId,
        time: Date.now(),
        ip: req.headers[`x-forwarded-for`],
        userAgent: req.headers[`user-agent`] ? req.headers[`user-agent`] : ``
    });

    // append session cookie to response
    res.cookie(`session`, newSessionID, {
        maxAge: 10000000000,
        ...SECURE_COOKIE_ATTRIBUTES
    });

    return res.redirect(`/2fa`);
});

app.use((req, res, next) => {
    if (DEBUG) return next();
    if (req.get(`Host`) === WEB_URL && req.get(`origin`) === WEBSCHEMA + `://` + WEB_URL && req.is(`application/json`)) {
        return next();
    }
    return res.send({ message: `Invalid location and/or type`, error: true });
});

// send link to login
app.post(`${BASE_URL}/v1/login`, async (req, res) => {
    const emailRegex = /^(([^<>()\[\]\\.,;:\s@`]{1,64}(\.[^<>()\[\]\\.,;:\s@`]+)*)|(`.{1,62}`))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]{1,63}\.)+[a-zA-Z]{2,63}))$/;

    if (!req.body || !req.body.email || !req.body.email.match(emailRegex)) {
        return errorWebResponse(res, { message: `invalid mail`, error: true });
    }
    const email = sanitize(xss(req.body.email));

    const a = await db.get(`login`).findOne({
        email
    });

    const token = generateToken(100);
    const preSessionId = generateToken(100);
    const link = `${WEBSCHEMA}://${WEB_URL}${BASE_URL}/v1/createsession?t=${token}`;
    if (a) {
        if (a.time + 1000 * 60 * REQUEST_NEW_MAGIC_LINK_MINUTES > Date.now()) {
            const wait = (a.time + 1000 * 60 * REQUEST_NEW_MAGIC_LINK_MINUTES - Date.now()) / 1000;
            return errorWebResponse(
                res,
                {
                    message: `Please wait another ${wait}s before requesting a new login mail`,
                    error: true
                },
                true
            );
        }
        db.get(`login`).findOneAndUpdate(
            {
                email
            },
            {
                $set: {
                    time: Date.now(),
                    token,
                    ip: req.headers[`x-forwarded-for`],
                    preSessionId
                }
            }
        );
    } else {
        db.get(`login`).insert({
            email,
            time: Date.now(),
            token,
            ip: req.headers[`x-forwarded-for`],
            preSessionId
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

    const { info, error } = await transporter.sendMail({
        headers: {
            "User-Agent": process.env.MAIL_AGENT,
            "X-Mailer": process.env.MAIL_AGENT,
            "Reply-To": process.env.REPLY_TO
        },
        from: `"${process.env.FROM_NAME}" <${process.env.FROM_MAIL_ADDRESS}>`,
        to: req.body.email,
        subject: process.env.FROM_NAME,
        text: `Someone requested a link to log into your account. If this was you: Open this link in your browser ${link} Never share this link with anyone!`,
        html: `Someone requested a link to log into your account. If this was you: Click on the link to <a href="${link}"><b>Login</b></a> <p style="color:red;"> <b>Never share this link with anyone!</b></p>`
    });

    if (error) return res.send({ message: `Could not send email`, error: true });

    console.log(error, info);

    res.cookie(`preSessionId`, preSessionId, {
        maxAge: 10000000,
        ...SECURE_COOKIE_ATTRIBUTES
    });
    res.cookie(`session`, ``, {
        maxAge: 1,
        ...SECURE_COOKIE_ATTRIBUTES
    });
    res.cookie(`firstFactorToken`, ``, {
        maxAge: 1,
        ...SECURE_COOKIE_ATTRIBUTES
    });
    return errorWebResponse(res, { message: `Success`, error: false }, true);
});

// two factor authentication
app.post(`${BASE_URL}/v1/2fa/totp/generate`, async (req, res) => {
    const a = await checkSession(req);
    if (!a) return errorWebResponse(res, { message: `invalid session`, error: true }, true);
    if (a.totpActive) {
        if (!req.body || !req.body.replace || req.body.replace !== `true`) {
            return errorWebResponse(res, { message: `totp already activated; send the body {replace:true} to override`, error: true, warning: `token is present` }, true);
        }
    }
    const secret = authenticator.generateSecret();
    const otpauth = authenticator.keyuri(a.userId, WEB_URL, secret);
    db.collection(`user`).findOneAndUpdate(
        {
            _id: a._id
        },
        {
            $set: {
                totpSecret: secret
            }
        }
    );

    qrcode.toDataURL(otpauth, (err, url) => {
        res.status(200).send({
            qrCode: url,
            secret
        });
    });
});

app.post(`${BASE_URL}/v1/2fa/totp/register`, async (req, res) => {
    const a = await checkSession(req);
    if (!a) return errorWebResponse(res, { message: `invalid session token`, error: true }, true);
    if (!req.body) return errorWebResponse(res, { message: `missing body`, error: true });
    if (!req.body.totp) return errorWebResponse(res, { message: `totp token missing`, error: true });
    if (authenticator.generate(a.totpSecret) === req.body.totp) {
        await db.collection(`user`).findOneAndUpdate(
            {
                _id: a._id
            },
            {
                $set: {
                    totpActive: true
                }
            }
        );
        return errorWebResponse(res, { message: `correct totp token`, error: false }, true);
    }
    return errorWebResponse(res, { message: `invalid totp token`, error: true }, true);
});

app.post(`${BASE_URL}/v1/2fa/webauthn/register/request`, async (req, res) => {
    const user = await checkSession(req);
    if (!user) return errorWebResponse(res, { message: `invalid session token`, error: true }, true);

    const challengeResponse = generateRegistrationChallenge({
        relyingParty: { name: process.env.DISPLAY_NAME },
        user: { id: user.userId, name: user.userId }
    });

    db.collection(`user`).findOneAndUpdate(
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

app.post(`${BASE_URL}/v1/2fa/webauthn/register/verify`, async (req, res) => {
    const user = await checkSession(req);
    if (!user) return errorWebResponse(res, { message: `invalid session token`, error: true }, true);

    const { key, challenge } = parseRegisterRequest(req.body);
    db.collection(`user`).findOne({ webAuthnRegisterChallenge: challenge });

    if (db.collection.length) {
        db.collection(`user`).findOneAndUpdate(
            {
                _id: user._id
            },
            {
                $set: {
                    webAuthnKey: key,
                    webAuthnActive: true,
                    webAuthnRegisterChallenge: false
                }
            }
        );
        return errorWebResponse(res, { message: `Success`, error: false }, true);
    }
    return errorWebResponse(res, { message: `WebAuthn challenge failed`, error: true }, true);
});

app.post(`${BASE_URL}/v1/createsession/2fa/totp`, async (req, res) => {
    if (!req.cookies) return errorWebResponse(res, { message: `missing cookies`, error: true });
    if (!req.cookies.firstFactorToken) return errorWebResponse(res, { message: `missing firstFactorToken cookie`, error: true });
    if (!req.body) return errorWebResponse(res, { message: `missing body`, error: true });
    if (!req.body.totp) return errorWebResponse(res, { message: `missing totp object in body`, error: true });

    const login = await db.get(`login`).findOne({ firstFactorToken: req.cookies.firstFactorToken });
    if (!login) return errorWebResponse(res, { message: `invalid firstFactorToken`, error: true });

    const user = await db.get(`user`).findOne({ userId: login.userId });
    if (authenticator.generate(user.totpSecret) === req.body.totp) {
        //generate session id
        const newSessionID = generateToken(100);

        //save session cookie to db
        await db.get(`session`).insert({
            session: newSessionID,
            userId: user.userId,
            time: Date.now(),
            ip: req.headers[`x-forwarded-for`],
            userAgent: req.headers[`user-agent`] ? req.headers[`user-agent`] : ``
        });

        //append session cookie to response
        res.cookie(`session`, newSessionID, {
            maxAge: 10000000000,
            ...SECURE_COOKIE_ATTRIBUTES
        });
        res.cookie(`firstFactorToken`, ``, {
            maxAge: 1,
            ...SECURE_COOKIE_ATTRIBUTES
        });

        return errorWebResponse(res, { message: `Success`, error: false }, true);
    }
    return errorWebResponse(res, { message: `invalid totp`, error: true }, true);
});

app.post(`${BASE_URL}/v1/createsession/2fa/webauthn/request`, async (req, res) => {
    if (!req.cookies) return errorWebResponse(res, { message: `missing cookies`, error: true });
    if (!req.cookies.firstFactorToken) return errorWebResponse(res, { message: `missing firstFactorToken cookie`, error: true });
    const fft = sanitize(xss(req.cookies.firstFactorToken));

    const login = await db.get(`login`).findOne({ firstFactorToken: fft });

    if (!login) return errorWebResponse(res, { message: `invalid firstFactorToken`, error: true });
    const user = await db.get(`user`).findOne({ userId: login.userId });
    if (!user) return errorWebResponse(res, { message: `user not found`, error: true });
    if (!user.webAuthnKey) return errorWebResponse(res, { message: `missing public key for this user`, error: true });

    const newChallenge = generateLoginChallenge(user.webAuthnKey);
    db.collection(`login`).findOneAndUpdate(
        {
            _id: login._id
        },
        {
            $set: {
                webAuthnLoginChallenge: newChallenge.challenge
            }
        }
    );
    newChallenge.userVerification = `preferred`;
    res.send(newChallenge);
});
app.post(`${BASE_URL}/v1/createsession/2fa/webauthn/verify`, async (req, res) => {
    if (!req.cookies) return errorWebResponse(res, { message: `missing cookies`, error: true });
    if (!req.cookies.firstFactorToken) return errorWebResponse(res, { message: `missing firstFactorToken cookie`, error: true });
    if (!req.body) return errorWebResponse(res, { message: `missing body`, error: true });
    const login = await db.get(`login`).findOne({ firstFactorToken: req.cookies.firstFactorToken });
    if (!login) return errorWebResponse(res, { message: `invalid firstFactorToken`, error: true });
    const user = await db.get(`user`).findOne({ userId: login.userId });
    if (!user) return errorWebResponse(res, { message: `user not found`, error: true });
    if (!user.webAuthnKey) return errorWebResponse(res, { message: `missing public key for this user`, error: true });

    const { challenge, keyId } = parseLoginRequest(req.body);

    if (!challenge) return errorWebResponse(res, { message: `missing challenge`, error: true });
    if (user.webAuthnKey.credID !== keyId) return errorWebResponse(res, { message: `invalid webAuthnKey`, error: true });
    if (login.webAuthnLoginChallenge !== challenge) return errorWebResponse(res, { message: `invalid challenge`, error: true });
    //solvedChallenge === login.webAuthnLoginChallenge
    if (verifyAuthenticatorAssertion(req.body, user.webAuthnKey)) {
        //generate session id
        const newSessionID = generateToken(100);

        //save session cookie to db
        await db.get(`session`).insert({
            session: newSessionID,
            userId: user.userId,
            time: Date.now(),
            ip: req.headers[`x-forwarded-for`],
            userAgent: req.headers[`user-agent`] ? req.headers[`user-agent`] : ``
        });

        //append session cookie to response
        res.cookie(`session`, newSessionID, {
            maxAge: 10000000000,
            ...SECURE_COOKIE_ATTRIBUTES
        });
        res.cookie(`firstFactorToken`, ``, {
            maxAge: 1,
            ...SECURE_COOKIE_ATTRIBUTES
        });

        return errorWebResponse(res, { message: `success`, error: false }, true);
    }
    return errorWebResponse(res, { message: `WebAuthn challenge failed`, error: true }, true);
});

app.post(`${BASE_URL}/v1/logout`, async (req, res) => {
    if (!req.cookies || !req.cookies.session) return errorWebResponse(res, { message: `missing cookies`, error: true });

    const sessionCookie = sanitize(xss(req.cookies.session));
    await db.get(`session`).findOneAndDelete({ session: sessionCookie });

    res.cookie(`session`, ``, {
        maxAge: 1,
        ...SECURE_COOKIE_ATTRIBUTES
    });
    return res.sendStatus(200);
});

app.post(`${BASE_URL}/v1/delete-account`, async (req, res) => {
    if (!req.cookies || !req.cookies.session) return errorWebResponse(res, { message: `missing cookies`, error: true });

    const user = await checkSession(req);
    if (!user) return errorWebResponse(res, { message: `invalid session`, error: true }, true);

    await db.get(`session`).findOneAndDelete({ session: sessionCookie });
    res.cookie(`session`, ``, {
        maxAge: 1,
        ...SECURE_COOKIE_ATTRIBUTES
    });
    await db.get(`user`).findOneAndDelete({ _id: user._id });
    return res.sendStatus(200);
});

app.get(`*`, (req, res) => {
    return res.sendStatus(404);
});
app.post(`*`, (req, res) => {
    return res.sendStatus(404);
});

// check session token
const checkSession = async req => {
    const sessionCookie = sanitize(xss(req.cookies.session));
    const session = await db.get(`session`).findOne({
        session: sessionCookie
    });
    if (!session) return false;
    const user = await db.get(`user`).findOne({
        userId: session.userId
    });
    if (!user) return false;
    return user;
};

// generate a random base 64 token
const generateToken = length => {
    return cryptoRandomString({ length, characters: `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-` });
};

// create a debug or default web response
const errorWebResponse = (res, responseObject, overrideDebug = false) => {
    if (overrideDebug || DEBUG) {
        return res
            .type("application/json")
            .status(responseObject.error ? 400 : 200)
            .send(responseObject);
    }
    return res.type("application/json").status(400).send({ message: `Error`, error: true });
};

module.exports = { app, BASE_URL, server };
