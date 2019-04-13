const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const Users = require('./users/users-model.js');
const session = require('express-session');

const sessionConfig = require('./auth/session-config.js');

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());
server.use(session(sessionConfig));

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
        req.session.user = user;
        res.status(200).json({ message: `Welcome ${user.username}` });
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.get('/api/logout', (req, res) => {
  if (req.session) {
    req.session.destroy(err => {
      if (err) {
        res.status(500).json({
          message:
            'error',
        });
      } else {
        res.status(200).json({ message: 'thanks for visiting' });
      }
    });
  } else {
    res.status(200).json({ message: 'thanks for visiting' });
  }
});

server.get('/api/users', loggedin, (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

function loggedin(req, res, next) {
    try {
      if (req && req.session && req.session.user) {
        next();
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    } catch (error) {
      res.status(500).json({ message: 'you broke it!' });
    }
}

const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
