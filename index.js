`use strict`;

const emailRegex = /^(([^<>()\[\]\\.,;:\s@`]{1,64}(\.[^<>()\[\]\\.,;:\s@`]+)*)|(`.{1,62}`))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]{1,63}\.)+[a-zA-Z]{2,63}))$/;
import dotenv from "dotenv";
dotenv.config();
import express from "express";
import cookieParser from "cookie-parser";
import compression from "compression";
import bodyParser from "body-parser";
import cryptoRandomString from "crypto-random-string";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import nodemailer from "nodemailer";
import xss from "xss";
import qrcode from "qrcode";
import { generateRegistrationChallenge, parseRegisterRequest, parseLoginRequest, generateLoginChallenge, verifyAuthenticatorAssertion } from "@firstdorsal/webauthn-server";
import { authenticator } from "otplib";

const DB_URL = process.env.DB_URL !== undefined ? process.env.DB_URL : `db`;

// init db: create the database on the pg server
import { initPg } from "./lib/initPg.js";
await initPg(DB_URL);

// connect to the db on the pg server
import pg from "pg";
const db = new pg.Client({
    user: "postgres",
    host: DB_URL,
    password: "password",
    database: "db"
});
db.connect().catch(() => {
    console.log("could not connect to database");
});

// create tables if not present
import { createTables } from "./lib/createTables.js";
await createTables(db);

// define and handle global variables
const WEBSCHEMA = process.env.WEB_SCHEMA != undefined ? process.env.WEB_SCHEMA : `https`;
const PORT = process.env.PORT !== undefined ? process.env.PORT : 80;
const WEB_URL = process.env.WEB_URL != undefined ? process.env.WEB_URL : `localhost`;
console.log(`server started on port ${PORT} with url ${WEBSCHEMA}://${WEB_URL}`);

const DEBUG = process.env.DEBUG || false;
console.log(`debug mode set to ${DEBUG}. ${DEBUG ? `DONT USE IN PRODUCTION` : ``}`);
const SECURE_COOKIE_ATTRIBUTES = { path: `/`, httpOnly: true, secure: true, sameSite: `Strict` };
const BASE_URL = `/interossea`;

const REQUEST_NEW_MAGIC_LINK_MINUTES = process.env.REQUEST_NEW_MAGIC_LINK_MINUTES !== undefined ? process.env.REQUEST_NEW_MAGIC_LINK_MINUTES : 0.5;

const MAGIC_LINK_EXPIRE_MINUTES = process.env.MAGIC_LINK_EXPIRE_MINUTES !== undefined ? process.env.MAGIC_LINK_EXPIRE_MINUTES : 10;

const IP_REQUEST_TIME_MINUTES = process.env.IP_REQUEST_TIME_MINUTES !== undefined ? process.env.IP_REQUEST_TIME_MINUTES : 10;

const IP_REQUEST_PER_TIME = process.env.IP_REQUEST_PER_TIME !== undefined ? process.env.IP_REQUEST_PER_TIME : 100;

const DISABLE_FRONTEND = process.env.DISABLE_FRONTEND !== undefined ? process.env.DISABLE_FRONTEND : true;

// create express and set settings
const app = express();
const server = app.listen(PORT);
app.use(cookieParser());
app.use(compression());
app.use(bodyParser.json({ limit: `10kb` }));
app.use(helmet.hidePoweredBy());
app.disable(`etag`);
app.use(BASE_URL, express.static(`public`));
app.set(`view engine`, `pug`);
app.set("trust proxy", true);
app.locals.basedir = `views`;

// apply rate limiting to login
app.use(
    `${BASE_URL}/v1/login`,
    rateLimit({
        windowMs: IP_REQUEST_TIME_MINUTES * 60 * 1000,
        max: IP_REQUEST_PER_TIME
    })
);

// frontend if enabled
app.get(`${BASE_URL}/`, (req, res) => {
    res.render(`index`);
});
if (!DISABLE_FRONTEND) {
    app.get(`${BASE_URL}/login`, (req, res) => {
        res.render(`login/index`);
    });
}

// handle clicked link
app.get(`${BASE_URL}/v1/createsession`, async (req, res) => {
    res.cookie(`sessionId`, ``, {
        maxAge: 1,
        ...SECURE_COOKIE_ATTRIBUTES
    });
    res.cookie(`preSessionId`, ``, {
        maxAge: 1,
        ...SECURE_COOKIE_ATTRIBUTES
    });

    // send error if token is missing
    if (!req.query) return webResponse(res, { message: `no query specified`, error: true });
    if (!req.query.t) return webResponse(res, { message: `no login token present`, error: true });

    // sanitize the token
    const token = xss(req.query.t);

    // find corresponding email for token t
    const login = (await db.query(/*sql*/ `SELECT * FROM "login" WHERE "token"=$1`, [token])).rows[0];

    // delete login
    await db.query(/*sql*/ `DELETE FROM "login" WHERE "token"=$1`, [token]);

    // check if token exists and hasnt expired
    const ip = req.ip;
    if (!login) return webResponse(res, { message: `Invalid login token`, error: true }, true);
    if (!login.time || login.time + 1000 * 60 * MAGIC_LINK_EXPIRE_MINUTES < Date.now()) {
        return webResponse(res, { message: `Expired login token`, error: true }, true);
    }
    // check if ip requesting the token is the same as ip trying to start a session with it
    if ((!DEBUG && !login.ip) || login.ip !== ip) {
        return webResponse(res, { message: `Request was sent from a different IP`, error: true }, true);
    }

    if (!req.cookies) return webResponse(res, { message: `missing cookies`, error: true });

    if (!req.cookies.preSessionId) return webResponse(res, { message: `missing preSessionId cookie: Request was sent from a different origin/browser?`, error: true }, true);

    // check if last request was sent from same browser
    if (!login.preSessionId || login.preSessionId !== req.cookies.preSessionId) {
        return webResponse(res, { message: `invalid preSessionId cookie: Request was sent from a different origin/browser?`, error: true }, true);
    }

    // try to find user with email
    let user = (await db.query(/*sql*/ `SELECT * FROM "users" WHERE "email"=$1`, [login.email])).rows[0];

    // create new user if dont exist
    if (!user) {
        const userId = `u${generateToken(14)}`;

        await db.query(/*sql*/ `INSERT INTO "users" ("email", "userId", "time") VALUES ($1, $2, $3)`, [login.email, userId, Date.now()]);
        user = { userId };
    } else if (user.totpActive || user.webAuthnActive) {
        // check if 2fa is present

        const firstFactorToken = generateToken(100);

        // add firstFactorToken to db
        await db.query(/*sql*/ `INSERT INTO "login2" ("firstFactorToken", "userId", "time", "ip") VALUES ($1, $2, $3, $4)`, [firstFactorToken, user.userId, Date.now(), ip]);

        // append firstFactorToken cookie to response
        res.cookie(`firstFactorToken`, firstFactorToken, {
            maxAge: 10000000,
            ...SECURE_COOKIE_ATTRIBUTES
        });

        if (user.totpActive && user.webAuthnActive) return res.redirect(`${DISABLE_FRONTEND ? "" : BASE_URL}/login/2fa`);
        if (user.totpActive) return res.redirect(`${DISABLE_FRONTEND ? "" : BASE_URL}/login/2fa/totp`);
        return res.redirect(`${DISABLE_FRONTEND ? "" : BASE_URL}/login/2fa/webauthn`);
    }
    // generate session id
    const newSessionID = generateToken(100);

    // save session cookie to db
    await db.query(/*sql*/ `INSERT INTO "sessions" ("sessionId", "userId", "time", "ip") VALUES ($1, $2, $3, $4)`, [newSessionID, user.userId, Date.now(), ip]);

    // append session cookie to response
    res.cookie(`sessionId`, newSessionID, {
        maxAge: 10000000000,
        ...SECURE_COOKIE_ATTRIBUTES
    });

    return res.redirect(`${DISABLE_FRONTEND ? "" : BASE_URL}/2fa`);
});

app.use((req, res, next) => {
    res.type("application/json");
    if (DEBUG) return next();
    if (req.get(`Host`) === WEB_URL && req.get(`origin`) === WEBSCHEMA + `://` + WEB_URL && req.is(`application/json`)) {
        return next();
    }
    return res.send({ message: `Invalid location and/or type`, error: true });
});

// send link to login
app.post(`${BASE_URL}/v1/login`, async (req, res) => {
    if (!req.body || !req.body.email || !req.body.email.match(emailRegex)) {
        return webResponse(res, { message: `invalid mail`, error: true });
    }
    const email = xss(req.body.email);
    const login = (await db.query(/*sql*/ `SELECT * FROM "login" WHERE "email"=$1`, [email])).rows[0];

    const token = generateToken(100);
    const preSessionId = generateToken(100);
    const link = `${WEBSCHEMA}://${WEB_URL}${BASE_URL}/v1/createsession?t=${token}`;
    const ip = req.ip;
    if (login) {
        // cooldown to send next link based on ip address
        if (login.time + 1000 * 60 * REQUEST_NEW_MAGIC_LINK_MINUTES > Date.now()) {
            const wait = (login.time + 1000 * 60 * REQUEST_NEW_MAGIC_LINK_MINUTES - Date.now()) / 1000;
            return webResponse(
                res,
                {
                    message: `Please wait another ${wait}s before requesting a new login mail`,
                    error: true
                },
                true
            );
        }
        db.query(/*sql*/ `UPDATE "login" SET time=$2, token=$3, ip=$4, "preSessionId"=$5 WHERE email=$1`, [email, Date.now(), token, ip, preSessionId]);
    } else {
        db.query(/*sql*/ `INSERT INTO "login" ("email", "time", "token", "ip", "preSessionId") VALUES ($1,$2,$3,$4,$5)`, [email, Date.now(), token, ip, preSessionId]);
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

    const { error } = await transporter.sendMail({
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

    res.cookie(`preSessionId`, preSessionId, {
        maxAge: 10000000,
        ...SECURE_COOKIE_ATTRIBUTES
    });
    res.cookie(`sessionId`, ``, {
        maxAge: 1,
        ...SECURE_COOKIE_ATTRIBUTES
    });
    res.cookie(`firstFactorToken`, ``, {
        maxAge: 1,
        ...SECURE_COOKIE_ATTRIBUTES
    });
    return webResponse(res, { message: `Success`, error: false }, true);
});

// two factor authentication
app.post(`${BASE_URL}/v1/2fa/totp/generate`, async (req, res) => {
    const user = await checkSession(req);
    if (!user) return webResponse(res, { message: `invalid session`, error: true }, true);
    if (user.totpActive) {
        if (!req.body || !req.body.replace || req.body.replace !== `true`) {
            return webResponse(res, { message: `totp already activated; send the body { replace: true } to override`, error: true, warning: `token is present` }, true);
        }
    }
    const secret = authenticator.generateSecret();
    const otpauth = authenticator.keyuri(user.userId, WEB_URL, secret);
    db.query(/*sql*/ `UPDATE "users" SET "totpSecret"=$2 WHERE "userId"=$1`, [user.userId, secret]);

    qrcode.toDataURL(otpauth, (err, qrCode) => {
        if (err) {
            console.log(err);
            return webResponse(res, { message: `failed to create qr code`, error: true });
        }
        return res.status(200).send({
            qrCode,
            secret,
            url: otpauth
        });
    });
});

app.post(`${BASE_URL}/v1/2fa/totp/register`, async (req, res) => {
    const user = await checkSession(req);
    if (!user) return webResponse(res, { message: `invalid session token`, error: true }, true);
    if (!req.body) return webResponse(res, { message: `missing body`, error: true });
    if (!req.body.totp) return webResponse(res, { message: `totp token missing`, error: true });
    if (authenticator.generate(user.totpSecret) === req.body.totp) {
        db.query(/*sql*/ `UPDATE "users" SET "totpActive"=true WHERE "userId"=$1`, [user.userId]);
        return webResponse(res, { message: `correct totp token`, error: false }, true);
    }
    return webResponse(res, { message: `invalid totp token`, error: true }, true);
});

app.post(`${BASE_URL}/v1/2fa/webauthn/register/request`, async (req, res) => {
    const user = await checkSession(req);
    if (!user) return webResponse(res, { message: `invalid session token`, error: true }, true);
    const challengeResponse = generateRegistrationChallenge({
        relyingParty: { name: process.env.DISPLAY_NAME, id: process.env.WEB_URL },
        user: { id: user.userId, name: user.userId }
    });
    await db.query(/*sql*/ `UPDATE "users" SET "webAuthnRegisterChallenge"=$2 WHERE "userId"=$1`, [user.userId, challengeResponse.challenge]);

    return res.send(challengeResponse);
});

app.post(`${BASE_URL}/v1/2fa/webauthn/register/verify`, async (req, res) => {
    const user = await checkSession(req);
    if (!user) return webResponse(res, { message: `invalid session token`, error: true }, true);

    const prr = parseRegisterRequest(req.body);
    if (DEBUG) console.log(prr, req.body);

    if (prr.key && prr.challenge === user.webAuthnRegisterChallenge) {
        db.query(/*sql*/ `UPDATE "users" SET "webAuthnKey"=$2, "webAuthnRegisterChallenge"=null, "webAuthnActive"=true WHERE "userId"=$1`, [user.userId, key]);
        return webResponse(res, { message: `Success`, error: false }, true);
    }
    return webResponse(res, { message: `WebAuthn challenge failed`, error: true }, true);
});

app.post(`${BASE_URL}/v1/2fa/createsession/totp`, async (req, res) => {
    if (!req.cookies) return webResponse(res, { message: `missing cookies`, error: true });
    if (!req.cookies.firstFactorToken) return webResponse(res, { message: `missing firstFactorToken cookie`, error: true });
    if (!req.body) return webResponse(res, { message: `missing body`, error: true });
    if (!req.body.totp) return webResponse(res, { message: `missing totp object in body`, error: true });

    const login = (await db.query(/*sql*/ `SELECT * FROM "login2" WHERE "firstFactorToken"=$1`, [req.cookies.firstFactorToken])).rows[0];
    if (!login) return webResponse(res, { message: `invalid firstFactorToken`, error: true });

    const user = (await db.query(/*sql*/ `SELECT * FROM "users" WHERE "userId"=$1`, [login.userId])).rows[0];
    if (authenticator.generate(user.totpSecret) === req.body.totp) {
        // generate session id
        const newSessionID = generateToken(100);

        // save session cookie to db
        await db.query(/*sql*/ `INSERT INTO "sessions" ("sessionId", "userId", "time", "ip") VALUES ($1, $2, $3, $4)`, [newSessionID, user.userId, Date.now(), req.ip]);

        // append session cookie to response
        res.cookie(`sessionId`, newSessionID, {
            maxAge: 10000000000,
            ...SECURE_COOKIE_ATTRIBUTES
        });
        // delete firstFactorToken cookie
        res.cookie(`firstFactorToken`, ``, {
            maxAge: 1,
            ...SECURE_COOKIE_ATTRIBUTES
        });

        return webResponse(res, { message: `Success`, error: false }, true);
    }
    return webResponse(res, { message: `invalid totp`, error: true }, true);
});

app.post(`${BASE_URL}/v1/2fa/createsession/webauthn/request`, async (req, res) => {
    if (!req.cookies) return webResponse(res, { message: `missing cookies`, error: true });
    if (!req.cookies.firstFactorToken) return webResponse(res, { message: `missing firstFactorToken cookie`, error: true });
    const login = (await db.query(/*sql*/ `SELECT * FROM "login2" WHERE "firstFactorToken"=$1`, [req.cookies.firstFactorToken])).rows[0];

    if (!login) return webResponse(res, { message: `invalid firstFactorToken`, error: true });

    const user = (await db.query(/*sql*/ `SELECT * FROM "users" WHERE "userId"=$1`, [login.userId])).rows[0];
    if (!user) return webResponse(res, { message: `user not found`, error: true });
    if (!user.webAuthnKey) return webResponse(res, { message: `missing public key for this user`, error: true });

    const newChallenge = generateLoginChallenge(user.webAuthnKey);
    db.query(/*sql*/ `UPDATE "login2" SET "webAuthnLoginChallenge"=$2 WHERE "firstFactorToken"=$1`, [login.firstFactorToken, newChallenge.challenge]);

    newChallenge.userVerification = `preferred`;
    res.send(newChallenge);
});

app.post(`${BASE_URL}/v1/2fa/createsession/webauthn/verify`, async (req, res) => {
    if (!req.cookies) return webResponse(res, { message: `missing cookies`, error: true });
    if (!req.cookies.firstFactorToken) return webResponse(res, { message: `missing firstFactorToken cookie`, error: true });
    if (!req.body) return webResponse(res, { message: `missing body`, error: true });
    const login = (await db.query(/*sql*/ `SELECT * FROM "login2" WHERE "firstFactorToken"=$1`, [req.cookies.firstFactorToken])).rows[0];
    if (!login) return webResponse(res, { message: `invalid firstFactorToken`, error: true });
    const user = (await db.query(/*sql*/ `SELECT * FROM "users" WHERE "userId"=$1`, [login.userId])).rows[0];
    if (!user) return webResponse(res, { message: `user not found`, error: true });
    if (!user.webAuthnKey) return webResponse(res, { message: `missing public key for this user`, error: true });

    const { challenge, keyId } = parseLoginRequest(req.body.credentials);

    if (!challenge) return webResponse(res, { message: `missing challenge`, error: true });
    if (user.webAuthnKey.credID !== keyId) return webResponse(res, { message: `invalid webAuthnKey`, error: true });
    if (login.webAuthnLoginChallenge !== challenge) return webResponse(res, { message: `invalid challenge`, error: true });
    // solvedChallenge === login.webAuthnLoginChallenge
    if (verifyAuthenticatorAssertion(req.body.credentials, user.webAuthnKey)) {
        // generate session id
        const newSessionID = generateToken(100);

        // save session cookie to db
        await db.query(/*sql*/ `INSERT INTO "sessions" ("sessionId", "userId", "time", "ip") VALUES ($1, $2, $3, $4)`, [newSessionID, user.userId, Date.now(), req.ip]);

        // append session cookie to response
        res.cookie(`sessionId`, newSessionID, {
            maxAge: 10000000000,
            ...SECURE_COOKIE_ATTRIBUTES
        });
        res.cookie(`firstFactorToken`, ``, {
            maxAge: 1,
            ...SECURE_COOKIE_ATTRIBUTES
        });

        return webResponse(res, { message: `success`, error: false }, true);
    }
    return webResponse(res, { message: `WebAuthn challenge failed`, error: true }, true);
});

app.post(`${BASE_URL}/v1/logout`, async (req, res) => {
    if (!req.cookies || !req.cookies.sessionId) return webResponse(res, { message: `missing cookies`, error: true });
    await db.query(/*sql*/ `DELETE FROM "sessions" WHERE "sessionId"=$1`, [req.cookies.sessionId]);
    res.cookie(`sessionId`, ``, {
        maxAge: 1,
        ...SECURE_COOKIE_ATTRIBUTES
    });
    return res.sendStatus(200);
});

app.post(`${BASE_URL}/v1/delete-account`, async (req, res) => {
    if (!req.cookies || !req.cookies.sessionId) return webResponse(res, { message: `missing cookies`, error: true });

    const user = await checkSession(req);
    if (!user) return webResponse(res, { message: `invalid session`, error: true }, true);

    await db.query(/*sql*/ `DELETE FROM "sessions" WHERE "sessionId"=$1`, [req.cookies.sessionId]);

    res.cookie(`sessionId`, ``, {
        maxAge: 1,
        ...SECURE_COOKIE_ATTRIBUTES
    });
    await db.query(`DELETE FROM "users" WHERE "userId"=$1`, [user.userId]);
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
    const session = (await db.query(/*sql*/ `SELECT * FROM "sessions" WHERE "sessionId"=$1`, [req.cookies.sessionId])).rows[0];
    if (!session) return false;
    const user = (await db.query(/*sql*/ `SELECT * FROM "users" WHERE "userId"=$1`, [session.userId])).rows[0];
    if (!user) return false;
    return user;
};

// generate a random base 64 token
const generateToken = length => {
    return cryptoRandomString({ length, characters: `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-` });
};

// create a debug or default web response
const webResponse = (res, responseObject, overrideDebug = false) => {
    if (overrideDebug || DEBUG) {
        return res
            .type("application/json")
            .status(responseObject.error ? 400 : 200)
            .send(responseObject);
    }
    return res.type("application/json").status(400).send({ message: `Error`, error: true });
};
export { app, BASE_URL, server, db };
