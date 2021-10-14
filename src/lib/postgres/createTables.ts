const query = /*sql*/ `
CREATE TABLE login (
    "email" varchar(254) NOT NULL UNIQUE,
    "time" bigint NOT NULL,
    "token" varchar(100) NOT NULL,
    "ip" varchar(50) NOT NULL,
    "preSessionId" varchar(100) NOT NULL,
    PRIMARY KEY (email)
);
CREATE TABLE login2 (
    "firstFactorToken" varchar(100) NOT NULL UNIQUE,
    "userId" char(15) NOT NULL,
    "time" bigint NOT NULL,
    "ip" varchar(50) NOT NULL,
    "webAuthnLoginChallenge" varchar(100),
    PRIMARY KEY ("firstFactorToken")
);
CREATE TABLE users (
    "email" varchar(254) NOT NULL UNIQUE,
    "userId" char(15) NOT NULL UNIQUE,
    "time" bigint NOT NULL,
    "totpSecret" varchar(100),
    "totpActive" boolean DEFAULT false,
    "webAuthnRegisterChallenge" varchar(100),
    "webAuthnActive" boolean DEFAULT false,
    "webAuthnKey" json,
    PRIMARY KEY ("userId")
);
CREATE TABLE sessions (
    "sessionId" char(100) NOT NULL,
    "userId" char(15) NOT NULL,
    "time" bigint NOT NULL,
    "ip" varchar(50) NOT NULL,
    PRIMARY KEY ("sessionId")
);
`;
import pg from "pg";

export const createTables = async (db: pg.Client) => {
    await db.query(query).catch(e => {
        if (e.code === "42P07") return console.log("tables already exist");
        return console.log(e);
    });
    console.log("created tables");
};
