import { Router } from 'express';
import { forgetPasswordController, loginController , logoutController, refreshTokenController, registerUserController , resetPassword, updateUserDetails, uploadAvtar, verifyEmailController, verifyForgetPasswordOTP } from '../controllers/user.controller.js';
import auth from '../middleware/auth.js';
import upload from '../middleware/multer.js';

const userRouter = Router();

userRouter.post('/register', registerUserController);
userRouter.post('/verify-email' , verifyEmailController);
userRouter.post('/login', loginController);
userRouter.post('/logout' , auth , logoutController);
userRouter.put('/upload-avtar' , auth , upload.single('avtar') , uploadAvtar);
userRouter.put('/update-details' , auth , updateUserDetails);
userRouter.put('/forget-password' , forgetPasswordController);
userRouter.put('/forgot-password-otp' , verifyForgetPasswordOTP);
userRouter.put('/reset-password' , resetPassword);
userRouter.post('/refersh-token' , refreshTokenController);


export default userRouter;