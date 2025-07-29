import express from 'express'
const app = express()
const port = 3000

import bodyParser from 'body-parser'
import signup from './routes/authentication/signup.js'
import login from './routes/authentication/login.js'

import cookieParser from 'cookie-parser'

import Joi from 'joi'

import cors from 'cors'
app.use(
    cors({
        origin: true,
        credentials: true,
    })
)

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

app.use(cookieParser())

app.get('/', (req, res) => {
    res.send('Hello World!')
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

    let data = await signup(user)

    let options = {
        maxAge: 3600000, // 1 hr expiry matched with token timer
        httpOnly: true, // not exposed to client side code
        sameSite: 'none', // api and website should be on same origins but just in case
        secure: true, // force transfer via HTTPS
    }

    if (data.ok) {
        res.cookie('token', data.token, options)

        res.send({ username: data.username, isNonProfit: data.isNonProfit })
    } else {
        res.send(data.err)
    }
})

app.post('/api/auth/login', async (req, res) => {
    let data = await login(req.body)

    let options = {
        maxAge: 3600000, // 1 hr expiry matched with token timer
        httpOnly: true, // not exposed to client side code
        sameSite: 'none', // api and website should be on same origins but just in case
        secure: true, // force transfer via HTTPS
    }

    if (data.ok) {
        res.cookie('token', data.token, options)

        res.send({ username: data.username, isNonProfit: data.isNonProfit })
    } else {
        res.send({ err: data.err })
    }
})

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})
