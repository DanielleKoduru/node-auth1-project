// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const express = require("express")
const bcrypt = require("bcryptjs")
const { checkUsernameFree, checkUsernameExists, checkPasswordLength } = require("../auth/auth-middleware")
const Users = require("../users/users-model")


const router = express.Router()

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

router.post("/api/auth/register", checkPasswordLength(), checkUsernameFree(), async (req, res, next) => {
  try {
    const { username, password } = req.body
    const hashPass = await bcrypt.hash(password, 8)
    const newUser = await Users.add({ username, password: hashPass })
    // console.log("hi")
    res.status(200).json({ user_id: newUser.user_id, username })
  } catch (err) {
    next(err)
  }
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

router.post("/api/auth/login", checkUsernameExists(), async (req, res, next) => {
  try {
    const { username, password } = req.body
    const user = await Users.findBy({ username })

    const passwordValid = await bcrypt.compare(password, user[0].password)

    if (!passwordValid) {
      return res.status(401).json({
        message: "Invalid credentials",
      })
    }

    req.session.chocolatechip = user

    res.status(200).json({
      message: `Welcome ${user[0].username}!`
    })
  } catch (err) {
    next(err)
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
router.get("/api/auth/logout", async (req, res, next) => {
  try {
    if (!req.session.user) {
      return res.status(200).json({
        message: "logged out"
      })
    }
    req.session.destroy((err) => {
      if (err) {
        return res.status(200).json({
          message: "logged out"
        })
      } else {
        res.status(200).json({
          message: "no session"
        })
      }
    })
  } catch (err) {
    next(err)
  }
})

module.exports = router