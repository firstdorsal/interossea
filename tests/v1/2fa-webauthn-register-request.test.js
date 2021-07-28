import dotenv from "dotenv";
import { BASE_URL, app, server, db } from "../../index.js";
import supertest from "supertest";

dotenv.config({ path: process.cwd() + "/tests/v1/.env" });
const request = supertest(app);
const URL1 = `${BASE_URL}/v1/createsession`;
const URL = `${BASE_URL}/v1/2fa/webauthn/register/request`;

test("requests a webauthn challenge", async () => {
    // create normal login and sessionId
    const loginResponse = await request.post(`${BASE_URL}/v1/login`).send({ email: process.env.RECIPIENT_ADDRESS });
    const loginResponseCookie = loginResponse.header["set-cookie"][0];
    const preSessionId = loginResponseCookie.substring(13, loginResponseCookie.indexOf(";"));
    const dbReponse = await db.query(/*sql*/ `SELECT token FROM "login" WHERE "email"=$1`, [process.env.RECIPIENT_ADDRESS]);
    const token = dbReponse.rows[0]?.token;
    const response = await request.get(`${URL1}?t=${token}`).set("Cookie", [`preSessionId=${preSessionId}`]);
    expect(response.status).toBe(302);
    const reponseCookie = response.header["set-cookie"][2];
    const sessionId = reponseCookie.substring(10, reponseCookie.indexOf(";"));

    // 2fa
    const response2 = await request.post(URL).set("Cookie", [`sessionId=${sessionId}`]);
    expect(response2.status).toBe(200);
    const dbReponse2 = await db.query(/*sql*/ `SELECT "webAuthnRegisterChallenge" FROM "users" WHERE "email"=$1`, [process.env.RECIPIENT_ADDRESS]);
    // compare the register challenge in the db with the register challenge that was received
    expect(response2.body.challenge).toBe(dbReponse2.rows[0].webAuthnRegisterChallenge);
});

afterAll(async () => {
    await server.close();
});
