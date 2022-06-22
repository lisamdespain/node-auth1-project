const router = require('express').Router();

const Users = require('../users/users-model')
const bcrypt = require('bcryptjs')

// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!

const {checkUsernameFree, checkUsernameExists, checkPasswordLength} = require('./auth-middleware')
/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */
router.post('/register', checkPasswordLength, 
  checkUsernameFree, (req, res, next)=>{
   const {username, password} = req.body
   const hash = bcrypt.hashSync(password, 12);
   Users.add({username, password: hash})
   .then(user =>{
       res.status(201).json(user)

   })
   .catch(next)
})

/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */
router.post('/login', checkUsernameExists, (req, res, next) =>{
  const {password} = req.body
  if (bcrypt.compareSync(password, req.user.password)){
    req.session.user = req.user;
    res.status(200).json({message: `Welcome ${req.body.username}!`})

   
  } else {
  res.status(401).json({message: "Invalid credentials"})
  return;
  }
})


/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */
  router.get('/logout', (req, res, next) => {
    if (req.session.user == null) {
        res.status(200).json({ message: `no session`})
        return;
    }
    req.session.destroy(err =>{{
        if (err != null){
            res.status(500).json({ message: `Log out failed.`})
            return;
        }
    }});
    res.status(200).json({ message: `logged out`})
});
 
// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router;