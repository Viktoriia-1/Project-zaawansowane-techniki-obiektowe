const Router = require('express')
const router = new Router()
const controller = require('./authController')
const {check} = require("express-validator")
const authMiddleware = require('./middleware/authMiddleware')
const roleMiddleware = require('./middleware/roleMiddleware')

router.post("/logout", controller.logout);

router.get("/protected", controller.tokenBlacklistMiddleware, (req, res) => {
    res.json({ message: "You have access to this route" });
});

router.post('/registration', [
    check('username', "Nazwa użytkownika nie może być pusta").notEmpty(),
    check('password', "Hasło musi mieć więcej niż 4 i mniej niż 10 znaków.").isLength({min:4, max:10})
],
     controller.registration)
     router.post('/login', controller.login)
     router.get('/users', roleMiddleware(["ADMIN"]), controller.getUsers)


module.exports = router;