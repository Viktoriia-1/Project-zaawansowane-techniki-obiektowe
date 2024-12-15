const User = require('./models/User')
const Role = require('./models/Role')
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { validationResult } = require('express-validator')
const {secret} = require("./config")
const TokenBlacklist = require("./models/TokenBlacklist");

const generateAccessToken = (id, roles) => {
    const payload = {
        id,
        roles
    }
    return jwt.sign(payload, secret, {expiresIn: "24h"} )
}


class authController {
    async registration(req, res) {
        try {
            const errors = validationResult(req)
            if (!errors.isEmpty()) {
                return res.status(400).json({message: "Błąd przy rejestracji", errors})
            }
            const {username, password} = req.body;
            const candidate = await User.findOne({username})
            if (candidate) {
                return res.status(400).json({message: "Użytkownik o tej nazwie już istnieje"})
            }
            const hashPassword = bcrypt.hashSync(password, 7);
            const userRole = await Role.findOne({value: "ADMIN"})
            const user = new User({username, password: hashPassword, roles: [userRole.value]})
            await user.save()
            return res.json({message:"Użytkownik został pomyślnie zarejestrowany"})
        }catch (e) {
            console.log(e)
            res.status(400).json({message: 'Błąd rejestracji'})
        }
    }

    async login(req, res) {
        try {
            const {username, password} = req.body
            const user = await User.findOne({username})
            if (!user) {
                return res.status(400).json({message: `Użytkownika ${username} nie ma`})
            }
            const validPassword = bcrypt.compareSync(password, user.password)
            if (!validPassword) {
                return res.status(400).json({message: `Błędne hasło`})
            }
            const token = generateAccessToken(user._id, user.roles)
            return res.json({token})
        }catch (e) {
            console.log(e)
            res.status(400).json({message: 'Błąd logowania'})
        }
    }

    async getUsers(req, res) {
        try {
                const users = await User.find()
                res.json(users)
            }catch (e) {
        }
    }
    async logout(req, res) {
        try {
            const authHeader = req.headers.authorization;
            if (!authHeader) {
                return res.status(401).json({ message: "No token provided" });
            }
    
            const token = authHeader.split(" ")[1];
            if (!token) {
                return res.status(401).json({ message: "Invalid token" });
            }
    
            await TokenBlacklist.create({ token });
    
            return res.json({ message: "Pomyślnie wylogowano" });
        } catch (e) {
            console.error(e);
            if (!res.headersSent) {
                return res.status(500).json({ message: "Błąd wylogowania" });
            }
        }
    }
    async tokenBlacklistMiddleware(req, res, next) {
        try {
            const authHeader = req.headers.authorization;
            if (!authHeader) {
                return res.status(401).json({ message: "Nieautoryzowany" });
            }

            const token = authHeader.split(" ")[1];
            if (!token) {
                return res.status(401).json({ message: "Nieautoryzowany" });
            }

            
            const blacklisted = await TokenBlacklist.findOne({ token });
            if (blacklisted) {
                return res.status(401).json({ message: "Token znajduje się na czarnej liście" });
            }

            next();
        } catch (e) {
            console.log(e);
            return res.status(500).json({ message: "Błąd sprawdzania tokena" });
        }
    }
}
module.exports = new authController()