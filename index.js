"use strict";
require(`dotenv`).config();
const express = require("express");
const app = express();
const nodemailer = require("nodemailer");
const db = require("monk")(process.env.DB, {
  useUnifiedTopology: true,
});
const crypto = require("crypto");

app.listen(process.env.PORT ? process.env.PORT : 80);
console.log("server started");

app.post("/login", async (req, res) => {
  if (!req.query || !req.query.email) {
    res.send("Error");
    return;
  }
  const a = await db.get("login").findOne({
    email: req.query.email,
  });
  const token = generateToken(100);
  const link = `${process.env.WEB_SCHEMA}://${process.env.WEB_URI}/createsession?t=${token}`;
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
    await db.get("login").findOneAndUpdate(
      {
        email: req.query.email,
      },
      {
        $set: {
          time: Date.now(),
          token,
          ip: req.headers["x-forwarded-for"],
        },
      }
    );
  } else {
    await db.get("login").insert({
      email: req.query.email,
      time: Date.now(),
      token,
      ip: req.headers["x-forwarded-for"],
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
      },
      from: `"${process.env.FROM_NAME}" <${process.env.LOGIN_MAIL_USERNAME}>`,
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
        res.send("OK");
      }
    }
  );
});

app.get("/createsession", async (req, res) => {
  if (!req.query || !req.query.t) {
    res.send("Error");
    return;
  }
  const a = await db.get("login").findOne({
    token: req.query.t,
  });
  if (!a || !a.time || a.time + 1000 * 60 * process.env.SLOWDOWN < Date.now()) {
    res.send("Invalid Token");
    return;
  }
  /* IMPLEMENT IN PRODUCTION
    if (!a.ip ||a.ip != req.headers['x-forwarded-for']) {
        res.send('Request was sent from a different IP');
        return;
    }*/
  await db.get("login").findOneAndDelete({
    token: req.query.t,
  });

  const b = await db.get("user").findOne({
    email: a.email,
  });
  if (!b) {
    //create new user if dont exist
    const userId = generateToken(10);

    await db.get("user").insert({
      userId,
      email: a.email,
      time: Date.now(),
      ip: req.headers["x-forwarded-for"],
    });
    b.userId = userId;
  }
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
  });

  res.redirect("/profile");
});

function generateToken(length) {
  return crypto
    .randomBytes(length)
    .toString("base64")
    .replace(/\//g, "_")
    .replace(/\+/g, "-")
    .replace(/\=/g, "");
}
