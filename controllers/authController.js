import bcrypt from 'bcryptjs';
import User from '../models/userModel.js';
import { generateToken } from '../config/auth.js'; // JWT生成関数を想定

export const registerUser = async (req, res) => {
  const { username, email, password } = req.body;

  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return res.status(400).json({ message: 'User already exists' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = new User({ username, email, password: hashedPassword });
  await newUser.save();

  res.status(201).json({ message: 'User registered successfully', user: newUser });
};

export const loginUser = async (req, res) => {
  const { username, email, password } = req.body;

  // ユーザーをusernameまたはemailで検索
  const user = await User.findOne({ $or: [{ username }, { email }] });
  if (!user) {
    return res.status(400).json({ message: 'User not found' });
  }

  // パスワードの確認
  const isPasswordCorrect = await bcrypt.compare(password, user.password);
  if (!isPasswordCorrect) {
    return res.status(400).json({ message: 'Invalid password' });
  }

  // アクセストークンとリフレッシュトークンを生成
  const token = generateToken(user._id, '15m'); // アクセストークン有効期限15分
  const refreshToken = generateToken(user._id, '30d'); // リフレッシュトークン有効期限30日

  // トークンをクッキーに設定
  res.cookie('token', token, { 
    httpOnly: true, 
    secure: process.env.NODE_ENV === 'production', 
    maxAge: 15 * 60 * 1000, // 15分
    sameSite: 'strict' 
  });

  res.cookie('refreshToken', refreshToken, { 
    httpOnly: true, 
    secure: process.env.NODE_ENV === 'production', 
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30日
    sameSite: 'strict' 
  });

  // レスポンスを送信
  res.status(200).json({ message: 'Login successful', token });
};
