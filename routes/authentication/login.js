import connectDB from '../../lib/mongoose.js'
import User from '../../models/user.js'
import { getJWT } from '../../lib/jwt.js'

import bcrypt from 'bcrypt'

export default async function login(data) {
    await connectDB()

    let user = await User.findOne({ username: data.username }).exec()
    if (user == null || user.length == 0) {
        console.log('user NOT found')
        return { ok: false, err: 'user not found' }
    }

    console.log('user found')
    
    const match = await bcrypt.compare(data.password, user.password)

    if (match) {
        console.log("passwords match")

        let token = await getJWT({ id: user._id })
        return {
            ok: true,
            token,
            username: user.username,
            isNonProfit: user.isNonProfit,
        }
    }

    console.log("user found, invalid password")
    return { ok: false, err: 'invalid password' }
}
