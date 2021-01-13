"use strict";
require(`dotenv`).config();
const express = require("express");
const app = express();
const nodemailer = require("nodemailer");
const db = require("monk")(process.env.DB_URI, {
  useUnifiedTopology: true,
});
const crypto = require("crypto");
const sanitize = require("mongo-sanitize");
const xss = require("xss");

app.listen(process.env.PORT != undefined ? process.env.PORT : 80);
console.log("server started");
db.get("login").drop();
const webSchema =
  process.env.WEB_SCHEMA != undefined ? process.env.WEB_SCHEMA : "https";

app.post("/akkount/login", async (req, res) => {
  if (
    !req.query ||
    !req.query.email ||
    !req.query.email.match(
      /^(([^<>()\[\]\\.,;:\s@"]{1,64}(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".{1,62}"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]{1,63}\.)+[a-zA-Z]{2,63}))$/
    )
  ) {
    res.send("Error");
    return;
  }
  const email = sanitize(xss(req.query.email));
  const redirect = sanitize(xss(req.query.from));

  const a = await db.get("login").findOne({
    email,
  });
  const token = generateToken(100);
  const preSessionId = generateToken(100);
  const link = `${webSchema}://${process.env.WEB_URI}/akkount/createsession?t=${token}`;
  if (a) {
    if (a.time + 1000 * 60 * process.env.SLOWDOWN > Date.now()) {
      const wait =
        (a.time + 1000 * 60 * process.env.SLOWDOWN - Date.now()) / 1000;
      res.send({
        message: `Please wait another ${wait}s before requesting a new login mail.`,
        seconds: wait,
      });
      return;
    }
    db.get("login").findOneAndUpdate(
      {
        email,
      },
      {
        $set: {
          time: Date.now(),
          token,
          ip: req.headers["x-forwarded-for"],
          preSessionId,
          redirect,
        },
      }
    );
  } else {
    db.get("login").insert({
      email,
      time: Date.now(),
      token,
      ip: req.headers["x-forwarded-for"],
      preSessionId,
      redirect,
    });
  }

  const transporter = nodemailer.createTransport({
    host: process.env.MAIL_HOST,
    port: 465,
    secure: true,
    tls: {
      rejectUnauthorized: true,
    },
    auth: {
      user: process.env.LOGIN_MAIL_USERNAME,
      pass: process.env.LOGIN_MAIL_PASSWORD,
    },
  });

  transporter.sendMail(
    {
      headers: {
        "User-Agent": process.env.MAIL_AGENT,
        "X-Mailer": process.env.MAIL_AGENT,
        "Reply-To": process.env.REPLY_TO,
      },
      from: `"${process.env.FROM_NAME}" <${process.env.FROM_MAIL_ADDRESS}>`,
      to: req.query.email,
      subject: process.env.FROM_NAME,
      text: `Someone requested a link to log into your account. If this was you: Open this link in your browser ${link} Never share this link with anyone!`,
      html: `Someone requested a link to log into your account. If this was you: Click on the link to <a href="${link}"><b>Login</b></a> <p style="color:red;"> <b>Never share this link with anyone!</b></p>`,
    },
    (error, info) => {
      if (error) {
        console.log(error);
        res.send("Invalid email");
      } else {
        res.cookie("preSession", preSessionId, {
          maxAge: 10000000000,
          path: "/",
          httpOnly: true,
          secure: true,
          sameSite: "Strict",
        });
        res.send("OK");
      }
    }
  );
});

app.get("/akkount/createsession", async (req, res) => {
  // send error if token is missing
  if (!req.query || !req.query.t) {
    res.send("Error");
    return;
  }
  //sanitize the token
  req.query.t = sanitize(xss(req.query.t));

  //find corresponding email for token
  const a = await db.get("login").findOne({
    token: req.query.t,
  });
  //delete token
  await db.get("login").findOneAndUpdate(
    {
      token: req.query.t,
    },
    {
      $set: {
        token: "",
      },
    }
  );
  //check if token exists and hasnt expired
  if (!a) {
    res.send("Invalid Token");
    return;
  }
  if (!a.time || a.time + 1000 * 60 * process.env.SLOWDOWN < Date.now()) {
    res.send("Expired Token");
    return;
  }
  //check if ip requesting the token is the same as ip trying to start a session with it
  if (!a.ip || a.ip != req.headers["x-forwarded-for"]) {
    res.send("Request was sent from a different IP");
    return;
  }
  const preSessionId = sanitize(xss(req.cookies.preSessionId));

  if (process.env.DEVELOPMENT === undefined) {
    //check if browser origin and device is the same
    if (!a.preSessionId || a.preSessionId != preSessionId) {
      res.send("Request was sent from a different origin/browser");
    }
  }
  //try to find user with email
  let b = await db.get("user").findOne({
    email: a.email,
  });
  const firstTime = !b;
  if (!b) {
    //create new user if dont exist
    const userId = generateToken(10);

    await db.get("user").insert({
      userId,
      email: a.email,
      time: Date.now(),
      ip: req.headers["x-forwarded-for"],
    });
    b = {
      userId,
    };
  }
  //generate session id
  const newSessionID = generateToken(100);

  //append session cookie
  res.cookie("session", newSessionID, {
    maxAge: 10000000000,
    path: "/",
    httpOnly: true,
    secure: true,
    sameSite: "Strict",
  });
  //save session cookie to db
  await db.get("session").insert({
    session: newSessionID,
    userId: b.userId,
    time: Date.now(),
    ip: req.headers["x-forwarded-for"],
    userAgent: req.headers["user-agent"] ? req.headers["user-agent"] : "",
  });
  /*
    //if redirect was specified at login redirect to location 
    */
  if (firstTime) {
    res.redirect("/profile");
    return;
  } else if (a.redirect != "undefined") {
    res.redirect("/" + a.redirect);
    return;
  }
  res.redirect("/anmelden");
});

app.get("*", (req, res) => {
  res.sendStatus(404);
});
app.post("*", (req, res) => {
  res.sendStatus(404);
});

function generateToken(length) {
  return crypto
    .randomBytes(length)
    .toString("base64")
    .replace(/\//g, "_")
    .replace(/\+/g, "-")
    .replace(/\=/g, "");
}
