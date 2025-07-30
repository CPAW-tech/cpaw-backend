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
        .setExpirationTime('2h')
        .sign(secretKey)
    return token
}

async function verifyJWT(token) {
    try {
        const { payload, protectedHeader } = await jwtVerify(token, secretKey, {
            issuer: process.env.JWT_ISSUER,
            audience: process.env.JWT_AUDIENCE,
        })

        return { ok: true, data: { payload, protectedHeader } }
    } catch (e) {
        return { ok: false, data: { err: 'invalid token' } }
    }
}

export { getJWT, verifyJWT }
