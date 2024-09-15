const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const session = require("express-session")
const KnexSessionStore = require("connect-session-knex")(session)
const usersRouter = require("./users/users-router")
const authRouter = require("./auth/auth-router")
const db = require("../data/db-config")

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());
server.use(session({
  name: "chocolatechip",
  resave: false,
  saveUninitialized: false,
  secret: "keep it secret keep it safe",
  store: new KnexSessionStore({
    knex: db,
    createtable: true,
  }),
}))

server.use(usersRouter)
server.use(authRouter)

server.get("/", (req, res) => {
  res.json({ api: "up" });
});

server.use((err, req, res, next) => { // eslint-disable-line
  res.status(500).json({
    message: err.message,
    stack: err.stack,
  });
});

module.exports = server;
