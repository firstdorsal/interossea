import pg from "pg";

export const initPg = async (DB_URL: string) => {
    try {
        const client = new pg.Client({
            user: "postgres",
            host: DB_URL,
            password: "password"
        });
        await client.connect();
        await client.query("CREATE DATABASE db").catch(() => {});
        await client.end();
    } catch (e) {
        console.log(e);
        console.log(`could not establish a connection to db`);
        process.exit(1);
    }
};
