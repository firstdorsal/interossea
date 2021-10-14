`use strict`;

const emailRegex =
    /^(([^<>()\[\]\\.,;:\s@`]{1,64}(\.[^<>()\[\]\\.,;:\s@`]+)*)|(`.{1,62}`))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]{1,63}\.)+[a-zA-Z]{2,63}))$/;
import dotenv from "dotenv";
dotenv.config();
import express, { CookieOptions, Request, Response } from "express";
import cookieParser from "cookie-parser";
import compression from "compression";
import bodyParser from "body-parser";
import cryptoRandomString from "crypto-random-string";
/*@ts-ignore*/
import integralhelm from "integralhelm";
import rateLimit from "express-rate-limit";
import nodemailer from "nodemailer";
import xss from "xss";
import qrcode from "qrcode";
import * as l from "./lib/lib.js";
import * as t from "./lib/types";
import { DataBase } from "./lib/Database.js";

import {
    generateRegistrationChallenge,
    parseRegisterRequest,
    parseLoginRequest,
    generateLoginChallenge,
    verifyAuthenticatorAssertion
    /*@ts-ignore*/
} from "@firstdorsal/webauthn-server";
import { authenticator } from "otplib";

const DB_URL = process.env.DB_URL !== undefined ? process.env.DB_URL : `db`;

const db = new DataBase({ type: "pg", dbUrl: DB_URL });

await db.init();

// define and handle global variables
const WEBSCHEMA = process.env.WEB_SCHEMA != undefined ? process.env.WEB_SCHEMA : `https`;
console.log(process.env.PORT, l.castableToNum(process.env.PORT), typeof process.env.PORT);

const PORT =
    process.env.PORT !== undefined && l.castableToNum(process.env.PORT)
        ? parseInt(process.env.PORT)
        : 80;
const WEB_URL = process.env.WEB_URL != undefined ? process.env.WEB_URL : `localhost`;
console.log(`server started on port ${PORT} with url ${WEBSCHEMA}://${WEB_URL}`);

const DEBUG = process.env.DEBUG !== undefined ? true : false;
console.log(`debug mode set to ${DEBUG}. ${DEBUG ? `DONT USE IN PRODUCTION` : ``}`);
const SECURE_COOKIE_ATTRIBUTES: CookieOptions = {
    path: `/`,
    httpOnly: true,
    secure: true,
    sameSite: `strict`
};
const BASE_URL = `/interossea`;

const REQUEST_NEW_MAGIC_LINK_MINUTES =
    process.env.REQUEST_NEW_MAGIC_LINK_MINUTES !== undefined &&
    l.castableToNum(process.env.REQUEST_NEW_MAGIC_LINK_MINUTES)
        ? parseInt(process.env.REQUEST_NEW_MAGIC_LINK_MINUTES)
        : 0.5;

const MAGIC_LINK_EXPIRE_MINUTES =
    process.env.MAGIC_LINK_EXPIRE_MINUTES !== undefined &&
    l.castableToNum(process.env.MAGIC_LINK_EXPIRE_MINUTES)
        ? parseInt(process.env.MAGIC_LINK_EXPIRE_MINUTES)
        : 10;

const IP_REQUEST_TIME_MINUTES =
    process.env.IP_REQUEST_TIME_MINUTES !== undefined &&
    l.castableToNum(process.env.IP_REQUEST_TIME_MINUTES)
        ? parseInt(process.env.IP_REQUEST_TIME_MINUTES)
        : 10;

const IP_REQUEST_PER_TIME =
    process.env.IP_REQUEST_PER_TIME !== undefined &&
    l.castableToNum(process.env.IP_REQUEST_PER_TIME)
        ? parseInt(process.env.IP_REQUEST_PER_TIME)
        : 100;

const ENABLE_FRONTEND =
    process.env.ENABLE_FRONTEND !== undefined ? process.env.ENABLE_FRONTEND : false;

// create express and set settings
const app = express();
const server = app.listen(PORT);
app.use(cookieParser());
app.use(compression());
app.use(
    integralhelm({
        helmet: {
            csp: {
                "font-src": ["'self'"],
                "style-src": ["'self'"],
                "img-src": ["'self'"],
                "script-src": ["'self'"],
                "connect-src": ["'self'"]
            }
        }
    })
);
app.use(bodyParser.json({ limit: `10kb` }));
app.use(BASE_URL, express.static(`public`));
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
if (ENABLE_FRONTEND) {
    app.set(`view engine`, `pug`);
    app.get(`${BASE_URL}/login`, (req, res) => {
        res.render(`login/index`);
    });
} else {
    console.log("frontend is disabled");
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
    if (!req.query) return webResponse(res, { message: `no query specified`, type: "error" });
    if (!req.query.t) return webResponse(res, { message: `no login token present`, type: "error" });

    // sanitize the token
    const token = xss(req.query.t.toString());

    // find corresponding email for token t
    const login = await db.getLogin(token);

    // delete login
    await db.deleteLogin(token);

    // check if token exists and hasnt expired
    const ip = req.ip;
    if (!login) return webResponse(res, { message: `Invalid login token`, type: "error" }, true);
    if (!login.time || login.time + 1000 * 60 * MAGIC_LINK_EXPIRE_MINUTES < Date.now()) {
        return webResponse(res, { message: `Expired login token`, type: "error" }, true);
    }
    // check if ip requesting the token is the same as ip trying to start a session with it
    if ((!DEBUG && !login.ip) || login.ip !== ip) {
        return webResponse(
            res,
            { message: `Request was sent from a different IP`, type: "error" },
            true
        );
    }

    if (!req.cookies) return webResponse(res, { message: `missing cookies`, type: "error" });

    if (!req.cookies.preSessionId)
        return webResponse(
            res,
            {
                message: `missing preSessionId cookie: Request was sent from a different origin/browser?`,
                type: "error"
            },
            true
        );

    // check if last request was sent from same browser
    if (!login.preSessionId || login.preSessionId !== req.cookies.preSessionId) {
        return webResponse(
            res,
            {
                message: `invalid preSessionId cookie: Request was sent from a different origin/browser?`,
                type: "error"
            },
            true
        );
    }

    // try to find user with email
    let user = await db.getUserByEmail(login.email);

    // create new user if dont exist
    if (!user) {
        const userId: t.UserID = `u${generateToken(14)}`;

        await db.createNewUser(login.email, userId);
        user = { userId } as t.User;
    } else if (user.totpActive || user.webAuthnActive) {
        // check if 2fa is present

        const firstFactorToken: t.FirstFactorToken = `fft${generateToken(97)}`;

        // add firstFactorToken to db
        await db.addFirstFactorToken(firstFactorToken, user.userId, login.ip);

        // append firstFactorToken cookie to response
        res.cookie(`firstFactorToken`, firstFactorToken, {
            maxAge: 10000000,
            ...SECURE_COOKIE_ATTRIBUTES
        });

        if (user.totpActive && user.webAuthnActive)
            return res.redirect(`${ENABLE_FRONTEND ? BASE_URL : ""}/login/2fa`);
        if (user.totpActive)
            return res.redirect(`${ENABLE_FRONTEND ? BASE_URL : ""}/login/2fa/totp`);
        return res.redirect(`${ENABLE_FRONTEND ? BASE_URL : ""}/login/2fa/webauthn`);
    }
    // generate session id
    const newSessionID: t.SessionID = `sid${generateToken(97)}`;

    // save session cookie to db
    await db.saveSessionID(newSessionID, user.userId, login.ip);

    // append session cookie to response
    res.cookie(`sessionId`, newSessionID, {
        maxAge: 10000000000,
        ...SECURE_COOKIE_ATTRIBUTES
    });

    return res.redirect(`${ENABLE_FRONTEND ? BASE_URL : ""}/2fa`);
});

app.use((req, res, next) => {
    res.type("application/json");
    if (DEBUG) return next();
    if (
        req.get(`Host`) === WEB_URL &&
        req.get(`origin`) === WEBSCHEMA + `://` + WEB_URL &&
        req.is(`application/json`)
    ) {
        return next();
    }
    return res.send({ message: `Invalid location and/or type`, error: true });
});

// send link to login
app.post(`${BASE_URL}/v1/login`, async (req, res) => {
    if (!req.body || !req.body.email || !req.body.email.match(emailRegex)) {
        return webResponse(res, { message: `invalid mail`, type: "error" });
    }
    const email = xss(req.body.email);
    const login = await db.getLoginByEmail(email);

    const token: t.EmailToken = `emt${generateToken(97)}`;
    const preSessionId: t.PreSessionID = `psid${generateToken(96)}`;
    const link = `${WEBSCHEMA}://${WEB_URL}${BASE_URL}/v1/createsession?t=${token}`;
    const ip = req.ip;
    if (login) {
        // cooldown to send next link based on ip address
        if (login.time + 1000 * 60 * REQUEST_NEW_MAGIC_LINK_MINUTES > Date.now()) {
            const wait =
                (login.time + 1000 * 60 * REQUEST_NEW_MAGIC_LINK_MINUTES - Date.now()) / 1000;
            return webResponse(
                res,
                {
                    message: `Please wait another ${wait}s before requesting a new login mail`,
                    type: "error"
                },
                true
            );
        }
        db.updateLogin(email, token, ip, preSessionId);
    } else {
        db.addNewLogin(email, token, ip, preSessionId);
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

    const headers: { [key: string]: string } = {};

    if (process.env.MAIL_AGENT !== undefined) {
        headers["User-Agent"] = process.env.MAIL_AGENT;
        headers["X-Mailer"] = process.env.MAIL_AGENT;
    }
    if (process.env.REPLY_TO !== undefined) headers["Reply-To"] = process.env.REPLY_TO;

    const sentMail = await transporter.sendMail({
        headers,
        from: `"${process.env.FROM_NAME}" <${process.env.FROM_MAIL_ADDRESS}>`,
        to: req.body.email,
        subject: process.env.FROM_NAME,
        text: `Someone requested a link to log into your account. If this was you: Open this link in your browser ${link} Never share this link with anyone!`,
        html: `Someone requested a link to log into your account. If this was you: Click on the link to <a href="${link}"><b>Login</b></a> <p style="color:red;"> <b>Never share this link with anyone!</b></p>`
    });

    if (!sentMail.accepted) return res.send({ message: `Could not send email`, error: true });

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
    return webResponse(res, { message: `Success`, type: "ok" }, true);
});

// two factor authentication
app.post(`${BASE_URL}/v1/2fa/totp/generate`, async (req, res) => {
    const user = await checkSession(req);
    if (!user) return webResponse(res, { message: `invalid session`, type: "error" }, true);
    if (user.totpActive) {
        if (!req.body || !req.body.replace || req.body.replace !== `true`) {
            return webResponse(
                res,
                {
                    message: `totp already activated; send the body { replace: true } to override`,
                    type: "error"
                },
                true
            );
        }
    }
    const secret: t.TOTPSecret = authenticator.generateSecret();
    const otpauth = authenticator.keyuri(user.userId, WEB_URL, secret);
    await db.updateTotpSecretForUser(user.userId, secret);

    qrcode.toDataURL(otpauth, (err, qrCode) => {
        if (err) {
            console.log(err);
            return webResponse(res, { message: `failed to create qr code`, type: "error" });
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
    if (!user) return webResponse(res, { message: `invalid session token`, type: "error" }, true);
    if (!req.body) return webResponse(res, { message: `missing body`, type: "error" });
    if (!req.body.totp) return webResponse(res, { message: `totp token missing`, type: "error" });
    if (authenticator.generate(user.totpSecret) === req.body.totp) {
        await db.enableTotpForUser(user.userId);
        return webResponse(res, { message: `correct totp token`, type: "ok" }, true);
    }
    return webResponse(res, { message: `invalid totp token`, type: "error" }, true);
});

app.post(`${BASE_URL}/v1/2fa/webauthn/register/request`, async (req, res) => {
    const user = await checkSession(req);
    if (!user) return webResponse(res, { message: `invalid session token`, type: "error" }, true);
    const challengeResponse = generateRegistrationChallenge({
        relyingParty: { name: process.env.DISPLAY_NAME, id: process.env.WEB_URL },
        user: { id: user.userId, name: user.userId }
    });

    await db.saveWebAuthnRegisterChallenge(user.userId, challengeResponse.challenge);

    return res.send(challengeResponse);
});

app.post(`${BASE_URL}/v1/2fa/webauthn/register/verify`, async (req, res) => {
    const user = await checkSession(req);
    if (!user) return webResponse(res, { message: `invalid session token`, type: "error" }, true);

    const prr = parseRegisterRequest(req.body.credentials);
    if (DEBUG) console.log(prr, "\n_______\n", req.body);

    if (prr.key && prr.challenge === user.webAuthnRegisterChallenge) {
        db.updateWebAuthnKey(user.userId, prr.key);
        return webResponse(res, { message: `Success`, type: "ok" }, true);
    }
    return webResponse(res, { message: `WebAuthn challenge failed`, type: "error" }, true);
});

app.post(`${BASE_URL}/v1/2fa/createsession/totp`, async (req, res) => {
    if (!req.cookies) return webResponse(res, { message: `missing cookies`, type: "error" });
    if (!req.cookies.firstFactorToken)
        return webResponse(res, { message: `missing firstFactorToken cookie`, type: "error" });
    if (!req.body) return webResponse(res, { message: `missing body`, type: "error" });
    if (!req.body.totp)
        return webResponse(res, { message: `missing totp object in body`, type: "error" });

    const login = await db.getAdvancedLogin(req.cookies.firstFactorToken);

    if (!login || !login.userId)
        return webResponse(res, { message: `invalid firstFactorToken`, type: "error" });

    const user = await db.getUserByUserId(login.userId);
    if (!user) return webResponse(res, { message: `invalid user`, type: "error" });
    if (authenticator.generate(user.totpSecret) === req.body.totp) {
        // generate session id
        const newSessionID: t.SessionID = `sid${generateToken(97)}`;

        // save session cookie to db
        await db.saveSessionID(newSessionID, user.userId, req.ip);

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

        return webResponse(res, { message: `Success`, type: "ok" }, true);
    }
    return webResponse(res, { message: `invalid totp`, type: "error" }, true);
});

app.post(`${BASE_URL}/v1/2fa/createsession/webauthn/request`, async (req, res) => {
    if (!req.cookies) return webResponse(res, { message: `missing cookies`, type: "error" });
    if (!req.cookies.firstFactorToken)
        return webResponse(res, { message: `missing firstFactorToken cookie`, type: "error" });
    const login = await db.getAdvancedLogin(req.cookies.firstFactorToken);

    if (!login || !login.userId)
        return webResponse(res, { message: `invalid firstFactorToken`, type: "error" });

    const user = await db.getUserByUserId(login.userId);

    if (!user) return webResponse(res, { message: `user not found`, type: "error" });
    if (!user.webAuthnKey)
        return webResponse(res, { message: `missing public key for this user`, type: "error" });

    const newChallenge = generateLoginChallenge(user.webAuthnKey);
    db.updateWebAuthnLoginChallenge(login.firstFactorToken, newChallenge.challenge);

    newChallenge.userVerification = `preferred`;
    res.send(newChallenge);
});

app.post(`${BASE_URL}/v1/2fa/createsession/webauthn/verify`, async (req, res) => {
    if (!req.cookies) return webResponse(res, { message: `missing cookies`, type: "error" });
    if (!req.cookies.firstFactorToken)
        return webResponse(res, { message: `missing firstFactorToken cookie`, type: "error" });
    if (!req.body) return webResponse(res, { message: `missing body`, type: "error" });
    const login = await db.getAdvancedLogin(req.cookies.firstFactorToken);

    if (!login || !login.userId)
        return webResponse(res, { message: `invalid firstFactorToken`, type: "error" });
    const user = await db.getUserByUserId(login.userId);

    if (!user) return webResponse(res, { message: `user not found`, type: "error" });
    if (!user.webAuthnKey)
        return webResponse(res, { message: `missing public key for this user`, type: "error" });

    const { challenge, keyId } = parseLoginRequest(req.body.credentials);

    if (!challenge) return webResponse(res, { message: `missing challenge`, type: "error" });
    if (user.webAuthnKey.credID !== keyId)
        return webResponse(res, { message: `invalid webAuthnKey`, type: "error" });
    if (login.webAuthnLoginChallenge !== challenge)
        return webResponse(res, { message: `invalid challenge`, type: "error" });
    // solvedChallenge === login.webAuthnLoginChallenge
    if (verifyAuthenticatorAssertion(req.body.credentials, user.webAuthnKey)) {
        // generate session id
        const newSessionID: t.SessionID = `sid${generateToken(97)}`;

        // save session cookie to db
        await db.saveSessionID(newSessionID, user.userId, req.ip);

        // append session cookie to response
        res.cookie(`sessionId`, newSessionID, {
            maxAge: 10000000000,
            ...SECURE_COOKIE_ATTRIBUTES
        });
        res.cookie(`firstFactorToken`, ``, {
            maxAge: 1,
            ...SECURE_COOKIE_ATTRIBUTES
        });

        return webResponse(res, { message: `success`, type: "ok" }, true);
    }
    return webResponse(res, { message: `WebAuthn challenge failed`, type: "error" }, true);
});

app.post(`${BASE_URL}/v1/logout`, async (req, res) => {
    if (!req.cookies || !req.cookies.sessionId)
        return webResponse(res, { message: `missing cookies`, type: "error" });
    await db.deleteSession(req.cookies.sessionId);

    res.cookie(`sessionId`, ``, {
        maxAge: 1,
        ...SECURE_COOKIE_ATTRIBUTES
    });
    return webResponse(res, { message: `success`, type: "ok" }, true);
});

app.post(`${BASE_URL}/v1/delete-account`, async (req, res) => {
    if (!req.cookies || !req.cookies.sessionId)
        return webResponse(res, { message: `missing cookies`, type: "error" });

    const user = await checkSession(req);
    if (!user) return webResponse(res, { message: `invalid session`, type: "error" }, true);

    await db.deleteSession(req.cookies.sessionId);

    res.cookie(`sessionId`, ``, {
        maxAge: 1,
        ...SECURE_COOKIE_ATTRIBUTES
    });
    await db.deleteUser(user.userId);
    return webResponse(res, { message: `success`, type: "ok" }, true);
});

app.post(`${BASE_URL}/v1/rml`, async (req, res) => {
    // a form of remote login to easily authorize yourself on a tv or any other device without email
    return webResponse(res, { message: `not implemented`, type: "error" }, true);
});

app.get(`*`, (req, res) => {
    return res.sendStatus(404);
});
app.post(`*`, (req, res) => {
    return res.sendStatus(404);
});

// check session token
const checkSession = async (req: Request) => {
    const session = await db.getSession(req.cookies.sessionId);
    if (!session) return false;

    const user = db.getUserByUserId(session.userId);
    if (!user) return false;
    return user;
};

// generate a random base 64 token
const generateToken = (length: number) => {
    return cryptoRandomString({
        length,
        characters: `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-`
    });
};

// create a debug or default web response
const webResponse = (res: Response, responseObject: t.WebResponse, overrideDebug = false) => {
    if (overrideDebug || DEBUG) {
        return res
            .type("application/json")
            .status(responseObject.type ? 400 : 200)
            .send(responseObject);
    }
    return res.type("application/json").status(400).send({ message: `Error`, error: true });
};

export { app, BASE_URL, server, db };
