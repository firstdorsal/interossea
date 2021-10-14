import { createTables } from "./postgres/createTables.js";
import { initPg } from "./postgres/initPg.js";
import pg from "pg";
export class DataBase {
    constructor(options) {
        this.init = async () => {
            if (this.type === "pg") {
                // connect to the db
                this.db = new pg.Client({
                    user: "postgres",
                    host: this.dbUrl,
                    password: "password",
                    database: "db"
                });
                // init db: create the database on the pg server
                await initPg(this.dbUrl);
                // connect to the db on the pg server
                this.db.connect().catch(() => {
                    console.log("could not connect to database");
                });
                // create tables if not present
                await createTables(this.db);
            }
        };
        this.getEmailForToken = async (token) => {
            if (this.type === "pg") {
                return (await this.db.query(/*sql*/ `SELECT * FROM "login" WHERE "token"=$1`, [token]))
                    .rows[0];
            }
        };
        this.deleteLoginForToken = async (token) => {
            if (this.type === "pg") {
                return this.db.query(/*sql*/ `DELETE FROM "login" WHERE "token"=$1`, [token]);
            }
        };
        this.getUserForEmail = async (email) => {
            if (this.type === "pg") {
                return (await this.db.query(/*sql*/ `SELECT * FROM "users" WHERE "email"=$1`, [email]))
                    .rows[0];
            }
            return false;
        };
        this.createNewUser = (email, userId) => {
            if (this.type === "pg") {
                return this.db.query(
                /*sql*/ `INSERT INTO "users" ("email", "userId", "time") VALUES ($1, $2, $3)`, [email, userId, Date.now()]);
            }
        };
        this.addFirstFactorToken = async (firstFactorToken, userId, ip) => {
            if (this.type === "pg") {
                return this.db.query(
                /*sql*/ `INSERT INTO "login2" ("firstFactorToken", "userId", "time", "ip") VALUES ($1, $2, $3, $4)`, [firstFactorToken, userId, Date.now(), ip]);
            }
        };
        this.saveSessionID = async (newSessionID, userId, ip) => {
            if (this.type === "pg") {
                return this.db.query(
                /*sql*/ `INSERT INTO "sessions" ("sessionId", "userId", "time", "ip") VALUES ($1, $2, $3, $4)`, [newSessionID, userId, Date.now(), ip]);
            }
        };
        this.getLoginForEmail = async (email) => {
            if (this.type === "pg") {
                return (await this.db.query(/*sql*/ `SELECT * FROM "login" WHERE "email"=$1`, [email]))
                    .rows[0];
            }
            return false;
        };
        this.addNewLogin = async (email, emailToken, ip, preSessionId) => {
            if (this.type === "pg") {
                return this.db.query(
                /*sql*/ `INSERT INTO "login" ("email", "time", "token", "ip", "preSessionId") VALUES ($1,$2,$3,$4,$5)`, [email, Date.now(), emailToken, ip, preSessionId]);
            }
        };
        this.updateLogin = async (email, emailToken, ip, preSessionId) => {
            if (this.type === "pg") {
                return this.db.query(
                /*sql*/ `UPDATE "login" SET time=$2, token=$3, ip=$4, "preSessionId"=$5 WHERE email=$1`, [email, Date.now(), emailToken, ip, preSessionId]);
            }
        };
        this.enableTotpForUser = async (userId) => {
            if (this.type === "pg") {
                return this.db.query(/*sql*/ `UPDATE "users" SET "totpActive"=true WHERE "userId"=$1`, [
                    userId
                ]);
            }
        };
        this.updateTotpSecretForUser = async (userId, secret) => {
            if (this.type === "pg") {
                return this.db.query(/*sql*/ `UPDATE "users" SET "totpSecret"=$2 WHERE "userId"=$1`, [
                    userId,
                    secret
                ]);
            }
        };
        this.saveWebAuthnRegisterChallenge = async (userId, challenge) => {
            if (this.type === "pg") {
                return this.db.query(
                /*sql*/ `UPDATE "users" SET "webAuthnRegisterChallenge"=$2 WHERE "userId"=$1`, [userId, challenge]);
            }
        };
        this.updateWebAuthnKey = async (userId, key) => {
            if (this.type === "pg") {
                return this.db.query(
                /*sql*/ `UPDATE "users" SET "webAuthnKey"=$2, "webAuthnRegisterChallenge"=null, "webAuthnActive"=true WHERE "userId"=$1`, [userId, key]);
            }
        };
        this.getUserForUserId = async (userId) => {
            if (this.type === "pg") {
                return (await this.db.query(/*sql*/ `SELECT * FROM "users" WHERE "userId"=$1`, [userId])).rows[0];
            }
            return false;
        };
        this.getAdvancedLoginForFFT = async (firstFactorToken) => {
            if (this.type === "pg") {
                return (await this.db.query(/*sql*/ `SELECT * FROM "login2" WHERE "firstFactorToken"=$1`, [
                    firstFactorToken
                ])).rows[0];
            }
            return false;
        };
        this.updateWebAuthnLoginChallenge = async (firstFactorToken, challenge) => {
            if (this.type === "pg") {
                return this.db.query(
                /*sql*/ `UPDATE "login2" SET "webAuthnLoginChallenge"=$2 WHERE "firstFactorToken"=$1`, [firstFactorToken, challenge]);
            }
        };
        this.deleteSession = async (sessionId) => {
            if (this.type === "pg") {
                return this.db.query(/*sql*/ `DELETE FROM "sessions" WHERE "sessionId"=$1`, [
                    sessionId
                ]);
            }
        };
        this.deleteUser = async (userId) => {
            if (this.type === "pg") {
                return this.db.query(`DELETE FROM "users" WHERE "userId"=$1`, [userId]);
            }
        };
        this.getSession = async (sessionId) => {
            if (this.type === "pg") {
                return (await this.db.query(/*sql*/ `SELECT * FROM "sessions" WHERE "sessionId"=$1`, [
                    sessionId
                ])).rows[0];
            }
            return false;
        };
        this.type = options.type;
        this.dbUrl = options.dbUrl;
    }
}
