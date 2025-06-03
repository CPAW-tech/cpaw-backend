import connectDB from '../../lib/mongoose.js'
import User from '../../models/user.js'
import { getJWT } from '../../lib/jwt.js'

export default async function signup(data) {
    await connectDB()
    const newUser = new User(data)

    try {
        let dbUser = await newUser.save()
        let token = await getJWT({ id: dbUser._id })

        console.log(newUser)

        return {
            ok: true,
            token,
            username: newUser.username,
            isNonProfit: newUser.isNonProfit,
        }
    } catch (e) {
        return { ok: false, err: e }
    }
}
