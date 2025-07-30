import connectDB from '../../lib/mongoose.js'
import User from '../../models/user.js'
import { getJWT } from '../../lib/jwt.js'

import bcrypt from 'bcrypt'

export default async function login(data) {
    await connectDB()

    let foundUser = await User.findOne({ username: data.username }).exec()
    if (!foundUser) {
        return { ok: false, data: 'Username not found.' }
    }

    const passwordsMatch = await bcrypt.compare(
        data.password,
        foundUser.password
    )

    if (passwordsMatch) {
        let token = await getJWT({ id: foundUser._id.toString() })
        console.log(foundUser._id.toString())
        return {
            ok: true,
            data: token,
        }
    }

    return { ok: false, data: 'Password Invalid.' }
}
