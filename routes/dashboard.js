import connectDB from '../lib/mongoose.js'
import User from '../models/user.js'

export default async function getUserData(id, filters = 'name username email') {
    await connectDB()

    let foundUser = await User.findOne({ _id: id }, filters).exec()
    if (!foundUser) {
        return { ok: false, data: new Error('User not found.') }
    }

    return { ok: true, data: foundUser }
}
