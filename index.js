const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const Users = require('./users/users-model.js');

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

server.use('/api/restricted/*', loggedin);

server.get('/api/restricted/*', (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

server.post('/api/register', (req, res) => {

  let user = req.body;
  user.password = bcrypt.hashSync(user.password, 4);
  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post('/api/login', (req, res) => {
  let { username, password } = req.body;
  Users.findBy({ username })
    .first()
    .then(user => {
    
      if (user && bcrypt.compareSync(password, user.password)) {
        res.status(200).json({ message: `Logged in` });
      } else {
        res.status(401).json({ message: 'You shall not pass!' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.get('/api/users', loggedin, (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

function loggedin(req, res, next) {
  const { username, password } = req.headers;

  if (username && password) {
    Users.findBy({ username })
      .first()
      .then(user => {
        if (user && bcrypt.compareSync(password, user.password)) {
          next();
        } else {
          res.status(401).json({ message: 'You shall not pass!' });
        }
      })
      .catch(error => {
        res.status(500).json(error);
      });
  } else {
    res.status(401).json({ message: 'You shall not pass!' });
  }
}

const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
