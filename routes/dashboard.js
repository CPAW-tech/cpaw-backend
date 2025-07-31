import connectDB from '../lib/mongoose.js'
import User from '../models/user.js'

export default async function getUserData(id, filters = 'name username email') {
    await connectDB()

    let foundUser = await User.findOne({ _id: id }, filters).exec()
    if (!foundUser) {
        return {
            ok: false,
            data: {
                error: {
                    name: 'DB_USER_NOT_FOUND',
                    message: 'User could not be found.',
                },
            },
        }
    }

    return { ok: true, data: foundUser }
}
