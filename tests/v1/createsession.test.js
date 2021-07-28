import dotenv from "dotenv";
import { BASE_URL, app, server, db } from "../../index.js";
import supertest from "supertest";

dotenv.config({ path: process.cwd() + "/tests/v1/.env" });
const request = supertest(app);
const URL = `${BASE_URL}/v1/createsession`;

test("requests to create a session without a login token query", async () => {
    const response = await request.get(URL);
    expect(response.status).toBe(400);
    expect(JSON.parse(response.text).message).toBe(`no login token present`);
});

test("requests to create a session with and empty login token query", async () => {
    const response = await request.get(`${URL}?t=`);
    expect(response.status).toBe(400);
    expect(JSON.parse(response.text).message).toBe(`no login token present`);
});

test("requests to create a session with an invalid login token", async () => {
    const response = await request.get(`${URL}?t=abc`);
    expect(response.status).toBe(400);
    expect(JSON.parse(response.text).message).toBe(`Invalid login token`);
});

// use db to get the token
test("requests to create a session with the valid token but no preSessionId", async () => {
    await request.post(`${BASE_URL}/v1/login`).send({ email: process.env.RECIPIENT_ADDRESS });
    const dbReponse = await db.query(/*sql*/ `SELECT token FROM "login" WHERE "email"=$1`, [process.env.RECIPIENT_ADDRESS]);
    const token = dbReponse.rows[0]?.token;
    const response = await request.get(`${URL}?t=${token}`);
    expect(response.status).toBe(400);
    expect(JSON.parse(response.text).message).toBe(`missing preSessionId cookie: Request was sent from a different origin/browser?`);
});

test("requests to create a session with the valid token and a invalid preSessionId", async () => {
    await request.post(`${BASE_URL}/v1/login`).send({ email: process.env.RECIPIENT_ADDRESS });
    const dbReponse = await db.query(/*sql*/ `SELECT token FROM "login" WHERE "email"=$1`, [process.env.RECIPIENT_ADDRESS]);
    const token = dbReponse.rows[0]?.token;
    const response = await request.get(`${URL}?t=${token}`).set("Cookie", ["preSessionId=abc"]);
    expect(response.status).toBe(400);
    expect(JSON.parse(response.text).message).toBe(`invalid preSessionId cookie: Request was sent from a different origin/browser?`);
});

test("requests to create a session with the valid token and a valid preSessionId", async () => {
    const loginResponse = await request.post(`${BASE_URL}/v1/login`).send({ email: process.env.RECIPIENT_ADDRESS });
    const loginResponseCookie = loginResponse.header["set-cookie"][0];
    const preSessionId = loginResponseCookie.substring(13, loginResponseCookie.indexOf(";"));
    const dbReponse = await db.query(/*sql*/ `SELECT token FROM "login" WHERE "email"=$1`, [process.env.RECIPIENT_ADDRESS]);
    const token = dbReponse.rows[0]?.token;
    const response = await request.get(`${URL}?t=${token}`).set("Cookie", [`preSessionId=${preSessionId}`]);
    expect(response.status).toBe(302);
});

// use actual email to get the token
/*
test("requests to create a session with the valid token and a valid preSessionId", async () => {
    const loginResponse = await request.post(`${BASE_URL}/v1/login`).send({ email: process.env.RECIPIENT_ADDRESS });
    const loginResponseCookie = loginResponse.header["set-cookie"][0];
    const preSessionId = loginResponseCookie.substring(13, loginResponseCookie.indexOf(";"));

    const imapResponse = 
    const token = "";
    const response = await request.get(`${URL}?t=${token}`).set("Cookie", [`preSessionId=${preSessionId}`]);
    expect(response.status).toBe(302);
});
*/
afterAll(async () => {
    await server.close();
});
