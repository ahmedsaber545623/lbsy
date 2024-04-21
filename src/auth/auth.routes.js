
import express  from "express";
import * as auth from "./auth.controller.js";

const authRouter=express.Router()

authRouter.post('/signup',auth.signUp)
authRouter.post('/signin',auth.signIn)
authRouter.get('/signin/showuser',auth.getAllUserSignIn)
authRouter.post('/signup/verify',auth.verifyOtp)

export default authRouter