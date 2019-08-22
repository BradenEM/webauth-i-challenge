const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const bcrypt = require("bcryptjs");

const Users = require("./users-model");

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

server.get("/", (req, res) => {
  res.send(`<h1>WEBAUTH MODULE 1</h1>`);
});

server.post("/api/register", async (req, res) => {
  let body = req.body;
  const hash = bcrypt.hashSync(body.password, 11);
  body.password = hash;
  const user = await Users.add(body);

  try {
    res.status(201).json(user);
  } catch (error) {
    res.status(500).json(error);
  }
});

server.post("/api/login", async (req, res) => {
  let { username, password } = req.body;
  const user = await Users.findBy({ username }).first();

  try {
    if (user && bcrypt.compareSync(password, user.password)) {
      res.status(200).json({ message: `Welcome ${user.username}` });
    } else {
      res.status(401).json({ message: "Invalid Credentials" });
    }
  } catch (error) {
    res.status(500).json(error);
  }
});

server.get("/api/users", validate, (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

function validate(req, res, next) {
  const { username, password } = req.headers;

  if (username && password) {
    Users.findBy({ username })
      .first()
      .then(user => {
        if (user && bcrypt.compareSync(password, user.password)) {
          next();
        } else {
          res.status(401).json({ message: "NOPE invalid credentials" });
        }
      })
      .catch(err => {
        res.status(500).json({ message: "unexpected error" });
      });
  } else {
    res.status(400).json({ message: "please provide the stuffs" });
  }
}

const port = process.env.PORT || 4000;
server.listen(port, () => console.log(`Server running on port ${port}`));
