import bcrypt from 'bcryptjs'
import User from '../models/userModel'
import { generateToken } from '../config/auth'

export const registerUser = async (req, res) => {
    const { username, email, password } = req.body;

    const existingUser = await User.findOne({ email});
    if(existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: 'User registered successfully', user: newUser });
  
};

export const loginUser = async (req, res) => {
  const { username, email, password } = req.body;

  const user = await User.findOne({ username });
  if(!user) {
    return res.status(400).json({ message: 'User not found' });
  }

  const isPasswordCorrect = await bcrypt.compare(password, user.password);
  if(!isPasswordCorrect) {
    return res.status(400).json({ message: 'Invalid password' });
  }

  const token = generateToken(user._id);
  res.status(200).json({ message: 'Login successful', token });

res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'strict' });

res.status(200).json({ message: 'Login successful' });
}