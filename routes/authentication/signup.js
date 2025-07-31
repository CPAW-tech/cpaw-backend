import connectDB from '../../lib/mongoose.js'
import User from '../../models/user.js'
import { getJWT } from '../../lib/jwt.js'

//TODO: check for same usernames and fail on collision
export default async function signup(data) {
    await connectDB()
    const newUser = new User(data)

    try {
        let dbUser = await newUser.save()
        let token = await getJWT({ id: dbUser._id })

        return {
            ok: true,
            data: token,
        }
    } catch (error) {
        return {
            ok: false,
            data: {
                error: {
                    name: 'DB_USER_NOT_FOUND',
                    message: 'User could not be created.',
                },
            },
        }
    }
}
