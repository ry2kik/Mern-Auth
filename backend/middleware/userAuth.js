import jwt from 'jsonwebtoken';

const userAuth = async (req, res, next) => {
    console.log(req.cookie);
    const { token } = req.cookies;

    if (!token) {
        return res.status(400).json({ success: true, mssg: 'Not authorized. Login again' });
    }

    try {
        const tokenDecode = jwt.verify(token, process.env.SECRET);
        if (tokenDecode.id) {
            req.body.userId = tokenDecode.id
        } else {
            return res.status(400).json({ success: false, mssg: 'Not authorized. Login Again' });
        }

        next();
    } catch(err) {
        return res.status(400).json({ success: false, mssg: err.message });
    }
}

export default userAuth;