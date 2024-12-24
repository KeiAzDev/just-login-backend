import jwt from 'jsonwebtoken'

export const generateToken = (userId, expiresIn) => {
    return jwt.sign({ id: userId }, process.env.JWT_SECRET, { expiresIn });
};
