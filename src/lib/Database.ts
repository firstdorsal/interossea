import { createTables } from "./postgres/createTables.js";
import { initPg } from "./postgres/initPg.js";
import pg from "pg";
import * as t from "./types";

export interface DbOptions {
    type: "pg" | "mongo";
    dbUrl: string;
}

export class DataBase {
    type: "pg" | "mongo";
    dbUrl: string;
    db: any;
    constructor(options: DbOptions) {
        this.type = options.type;
        this.dbUrl = options.dbUrl;
    }

    init = async () => {
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
    getLogin = async (token: string): Promise<t.Login | undefined> => {
        if (this.type === "pg") {
            return (await this.db.query(/*sql*/ `SELECT * FROM "login" WHERE "token"=$1`, [token]))
                .rows[0];
        }
    };
    deleteLogin = async (token: string) => {
        if (this.type === "pg") {
            return this.db.query(/*sql*/ `DELETE FROM "login" WHERE "token"=$1`, [token]);
        }
    };
    getUserByEmail = async (email: t.Email): Promise<t.User | false> => {
        if (this.type === "pg") {
            return (await this.db.query(/*sql*/ `SELECT * FROM "users" WHERE "email"=$1`, [email]))
                .rows[0];
        }
        return false;
    };
    createNewUser = (email: t.Email, userId: t.UserID) => {
        if (this.type === "pg") {
            return this.db.query(
                /*sql*/ `INSERT INTO "users" ("email", "userId", "time") VALUES ($1, $2, $3)`,
                [email, userId, Date.now()]
            );
        }
    };
    addFirstFactorToken = async (
        firstFactorToken: t.FirstFactorToken,
        userId: t.UserID,
        ip: t.IP
    ) => {
        if (this.type === "pg") {
            return this.db.query(
                /*sql*/ `INSERT INTO "login2" ("firstFactorToken", "userId", "time", "ip") VALUES ($1, $2, $3, $4)`,
                [firstFactorToken, userId, Date.now(), ip]
            );
        }
    };
    saveSessionID = async (newSessionID: t.SessionID, userId: t.UserID, ip: t.IP) => {
        if (this.type === "pg") {
            return this.db.query(
                /*sql*/ `INSERT INTO "sessions" ("sessionId", "userId", "time", "ip") VALUES ($1, $2, $3, $4)`,
                [newSessionID, userId, Date.now(), ip]
            );
        }
    };
    getLoginByEmail = async (email: t.Email): Promise<t.Login | false> => {
        if (this.type === "pg") {
            return (await this.db.query(/*sql*/ `SELECT * FROM "login" WHERE "email"=$1`, [email]))
                .rows[0];
        }
        return false;
    };

    addNewLogin = async (
        email: t.Email,
        emailToken: t.EmailToken,
        ip: t.IP,
        preSessionId: t.PreSessionID
    ) => {
        if (this.type === "pg") {
            return this.db.query(
                /*sql*/ `INSERT INTO "login" ("email", "time", "token", "ip", "preSessionId") VALUES ($1,$2,$3,$4,$5)`,
                [email, Date.now(), emailToken, ip, preSessionId]
            );
        }
    };
    updateLogin = async (
        email: t.Email,
        emailToken: t.EmailToken,
        ip: t.IP,
        preSessionId: t.PreSessionID
    ) => {
        if (this.type === "pg") {
            return this.db.query(
                /*sql*/ `UPDATE "login" SET time=$2, token=$3, ip=$4, "preSessionId"=$5 WHERE email=$1`,
                [email, Date.now(), emailToken, ip, preSessionId]
            );
        }
    };
    enableTotpForUser = async (userId: t.UserID) => {
        if (this.type === "pg") {
            return this.db.query(/*sql*/ `UPDATE "users" SET "totpActive"=true WHERE "userId"=$1`, [
                userId
            ]);
        }
    };
    updateTotpSecretForUser = async (userId: t.UserID, secret: t.TOTPSecret) => {
        if (this.type === "pg") {
            return this.db.query(/*sql*/ `UPDATE "users" SET "totpSecret"=$2 WHERE "userId"=$1`, [
                userId,
                secret
            ]);
        }
    };

    saveWebAuthnRegisterChallenge = async (userId: t.UserID, challenge: t.WebAuthnChallenge) => {
        if (this.type === "pg") {
            return this.db.query(
                /*sql*/ `UPDATE "users" SET "webAuthnRegisterChallenge"=$2 WHERE "userId"=$1`,
                [userId, challenge]
            );
        }
    };
    updateWebAuthnKey = async (userId: t.UserID, key: t.WebAuthnKey) => {
        if (this.type === "pg") {
            return this.db.query(
                /*sql*/ `UPDATE "users" SET "webAuthnKey"=$2, "webAuthnRegisterChallenge"=null, "webAuthnActive"=true WHERE "userId"=$1`,
                [userId, key]
            );
        }
    };
    getUserByUserId = async (userId: t.UserID): Promise<t.User | false> => {
        if (this.type === "pg") {
            return (
                await this.db.query(/*sql*/ `SELECT * FROM "users" WHERE "userId"=$1`, [userId])
            ).rows[0];
        }
        return false;
    };
    getAdvancedLogin = async (firstFactorToken: t.FirstFactorToken): Promise<t.Login | false> => {
        if (this.type === "pg") {
            return (
                await this.db.query(/*sql*/ `SELECT * FROM "login2" WHERE "firstFactorToken"=$1`, [
                    firstFactorToken
                ])
            ).rows[0];
        }
        return false;
    };
    updateWebAuthnLoginChallenge = async (
        firstFactorToken: t.FirstFactorToken,
        challenge: t.WebAuthnChallenge
    ) => {
        if (this.type === "pg") {
            return this.db.query(
                /*sql*/ `UPDATE "login2" SET "webAuthnLoginChallenge"=$2 WHERE "firstFactorToken"=$1`,
                [firstFactorToken, challenge]
            );
        }
    };

    deleteSession = async (sessionId: t.SessionID) => {
        if (this.type === "pg") {
            return this.db.query(/*sql*/ `DELETE FROM "sessions" WHERE "sessionId"=$1`, [
                sessionId
            ]);
        }
    };
    deleteUser = async (userId: t.UserID) => {
        if (this.type === "pg") {
            return this.db.query(/*sql*/ `DELETE FROM "users" WHERE "userId"=$1`, [userId]);
        }
    };

    getSession = async (sessionId: t.SessionID): Promise<t.Session | false> => {
        if (this.type === "pg") {
            return (
                await this.db.query(/*sql*/ `SELECT * FROM "sessions" WHERE "sessionId"=$1`, [
                    sessionId
                ])
            ).rows[0];
        }
        return false;
    };
}
