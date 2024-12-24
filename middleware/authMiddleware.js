import jwt from 'jsonwebtoken';

const authMiddleware = (req, res, next) => {
  const token = req.cookies.token;
  
  if (!token) {
    // トークンがない場合、リフレッシュトークンでアクセストークンを更新
    const refreshToken = req.cookies.refreshToken;
    
    if (!refreshToken) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    
    // リフレッシュトークンがあればアクセストークンを再発行
    try {
      const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
      const newAccessToken = jwt.sign({ id: decoded.id }, process.env.JWT_SECRET, { expiresIn: '15m' });

      // 新しいアクセストークンをクッキーに設定
      res.cookie('token', newAccessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 15 * 60 * 1000, // 15分
        sameSite: 'strict',
      });

      req.user = decoded; // ユーザー情報をリクエストに追加
      next(); // リクエストを次の処理に渡す
    } catch (error) {
      return res.status(401).json({ message: 'Invalid refresh token' });
    }
  } else {
    // 通常のトークンが有効であれば、それを使って認証
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decoded;
      next(); // リクエストを次の処理に渡す
    } catch (error) {
      return res.status(401).json({ message: 'Invalid token' });
    }
  }
};

export default authMiddleware;
