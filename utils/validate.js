export const validateLogin = (username, email, password) => {
  if(!username || !email || !password) {
    return { error: 'All fields are required' };
  }
  return null;
};
