import express from 'express';
import {
  registerUser,
  loginUser,
  logoutUser,
  getCurrentUser,
  refreshToken,
  isAuthenticated,
  home
} from '../controllers/authController.js';

const router = express.Router();

router.post('/register', registerUser);
router.post('/login', loginUser);
router.post('/logout', logoutUser);
router.get('/current-user', getCurrentUser);
router.post('/refresh-token', refreshToken);
router.get('/is-authenticated', isAuthenticated);
router.get('/home', home);

export default router;