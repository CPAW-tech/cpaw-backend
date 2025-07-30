import express from 'express'
const app = express()
const port = 3000

import bodyParser from 'body-parser'
import signup from './routes/authentication/signup.js'
import login from './routes/authentication/login.js'

import cookieParser from 'cookie-parser'

import Joi from 'joi'

import cors from 'cors'
import { verifyJWT } from './lib/jwt.js'
app.use(
    cors({
        origin: true,
        credentials: true,
    })
)

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

app.use(cookieParser()) //access cookies with req.cookies

// MIDDLEWARE
async function checkJWTCookie(req, res, next) {
    if (!req.cookies.token) {
        return res.status(401).json({
            ok: false,
            data: {
                error: 'Unauthorized: No token provided.',
            },
            metadata: {
                timestamp: Date.now(),
                endpoint: 'authentication middleware',
            },
        })
    }

    try {
        let { ok, data } = await verifyJWT(req.cookies.token)

        next()
    } catch (err) {
        res.status(401).json({
            ok: false,
            data: {
                error: new Error('Cookie Not Parsed Properly.'),
            },
            metadata: {
                timestamp: Date.now(),
                endpoint: 'authentication middleware',
            },
        })
    }
}

app.get('/', (req, res) => {
    res.send('Hello World!')
})

app.get('/api/dashboard', checkJWTCookie, (req, res) => {
    res.status(200).json({
        ok: true,
        data: {},
        metadata: {
            timestamp: Date.now(),
            endpoint: '/api/dashboard',
        },
    })
})

// AUTHENTICATION
app.post('/api/auth/signup', async (req, res) => {
    //
    const userSchema = Joi.object({
        name: Joi.object({
            fname: Joi.string().alphanum().min(1).max(100).trim().required(),
            lname: Joi.string().alphanum().min(1).max(100).trim().required(),
        }),
        username: Joi.string().alphanum().min(1).max(100).trim().required(),
        email: Joi.string().email().min(1).max(200).trim().required(),
        password: Joi.string()
            .min(1)
            .max(100)
            .pattern(/^[a-zA-Z0-9!@#$%^&*]+$/)
            .trim()
            .required(),
        isNonProfit: Joi.boolean().required(),
    })

    const { value: user, error } = userSchema.validate(req.body)

    // return error if form data is not formatted right
    if (error) {
        res.status(400).json({
            ok: false,
            data: {
                error,
            },
            metadata: {
                timestamp: Date.now(),
                endpoint: '/api/auth/signup',
            },
        })
    }

    let { ok, data } = await signup(user)

    let options = {
        maxAge: 3600000, // 1 hr expiry matched with token timer
        httpOnly: true, // not exposed to client side code
        sameSite: 'none', // api and website should be on same origins but just in case
        secure: true, // force transfer via HTTPS
    }

    if (ok) {
        res.status(201)
            .cookie('token', data, options)
            .json({
                ok: true,
                data: {},
                metadata: {
                    timestamp: Date.now(),
                    endpoint: '/api/auth/signup',
                },
            })
    } else {
        res.status(500).json({
            ok: false,
            data: {
                error: data,
            },
            metadata: {
                timestamp: Date.now(),
                endpoint: '/api/auth/signup',
            },
        })
    }
})

app.post('/api/auth/login', async (req, res) => {
    const userSchema = Joi.object({
        username: Joi.string().alphanum().min(1).max(100).trim().required(),
        password: Joi.string()
            .min(1)
            .max(100)
            .pattern(/^[a-zA-Z0-9!@#$%^&*]+$/)
            .trim()
            .required(),
    })

    const { value: user, error } = userSchema.validate(req.body)

    // return error if form data is not formatted right
    if (error) {
        res.status(400).json({
            ok: false,
            data: {
                error,
            },
            metadata: {
                timestamp: Date.now(),
                endpoint: '/api/auth/login',
            },
        })
    }

    let { ok, data } = await login(user)

    let options = {
        maxAge: 3600000, // 1 hr expiry matched with token timer
        httpOnly: true, // not exposed to client side code
        sameSite: 'none', // api and website should be on same origins but just in case
        secure: true, // force transfer via HTTPS
    }

    if (ok) {
        res.status(200)
            .cookie('token', data, options)
            .json({
                ok: true,
                data: {},
                metadata: {
                    timestamp: Date.now(),
                    endpoint: '/api/auth/login',
                },
            })
    } else {
        res.status(500).json({
            ok: false,
            data: {
                error: data,
            },
            metadata: {
                timestamp: Date.now(),
                endpoint: '/api/auth/login',
            },
        })
    }
})

app.get('/api/auth/protected', async (req, res) => {
    let {
        ok,
        data: { payload, protectedHeader },
    } = await verifyJWT(req.cookies.token)

    if (ok) {
        console.log(payload.id)
    }
})

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})
