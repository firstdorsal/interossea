import dotenv from "dotenv";
dotenv.config({ path: process.cwd() + "/tests/v1/.env" });

import { BASE_URL, app, server } from "../../index.js";
import supertest from "supertest";
const request = supertest(app);
const URL = `${BASE_URL}/v1/login`;

test("requests a login mail without sending data", async () => {
    const response = await request.post(URL);
    expect(response.status).toBe(400);
    expect(JSON.parse(response.text).message).toBe(`invalid mail`);
});

test("requests a login mail with an invalid field", async () => {
    const response = await request.post(URL).send({ x: "test" });
    expect(response.status).toBe(400);
    expect(JSON.parse(response.text).message).toBe(`invalid mail`);
});

test("requests a login mail with an invalid email", async () => {
    const response = await request.post(URL).send({ email: "test" });
    expect(response.status).toBe(400);
    expect(JSON.parse(response.text).message).toBe(`invalid mail`);
});

test("requests a login mail with a valid email", async () => {
    const response = await request.post(URL).send({ email: process.env.RECIPIENT_ADDRESS });
    expect(response.status).toBe(200);
    expect(JSON.parse(response.text).message).toBe(`Success`);
});

test("requests a second login in mail", async () => {
    const response = await request.post(URL).send({ email: process.env.RECIPIENT_ADDRESS });
    expect(response.status).toBe(400);
    expect(JSON.parse(response.text).message).toContain(`Please wait another`);
});

afterAll(async () => {
    await server.close();
});
