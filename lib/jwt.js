import crypto from 'crypto'
import { SignJWT, jwtVerify } from 'jose'
import 'dotenv/config'

const secretKey = crypto.createSecretKey(process.env.JWT_SECRET, 'utf-8')

async function getJWT(payload) {
    const token = await new SignJWT(payload)
        .setProtectedHeader({
            alg: 'HS256',
        })
        .setIssuedAt()
        .setIssuer(process.env.JWT_ISSUER)
        .setAudience(process.env.JWT_AUDIENCE)
        .setExpirationTime(3600000)
        .sign(secretKey)
    return token
}

async function verifyJWT(req) {
    const token = req.header('Authorization').replace('Bearer ', '')

    try {
        const { payload, protectedHeader } = await jwtVerify(token, secretKey, {
            issuer: process.env.JWT_ISSUER,
            audience: process.env.JWT_AUDIENCE,
        })

        return { ok: true, payload, protectedHeader }
    } catch (e) {
        return { ok: false, err: 'invalid token' }
    }
}

export { getJWT, verifyJWT }
