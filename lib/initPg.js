const { Client } = require(`pg`);

const initPg = async DB_URL => {
    const client = new Client({
        user: "postgres",
        host: DB_URL,
        password: "password"
    });
    await client.connect();
    await client.query("CREATE DATABASE db").catch(() => {});
    await client.end();
};

module.exports = initPg;
