
import express  from "express";
import * as users from "./user.controller.js";

const userRouter=express.Router()

userRouter.route('/')
.post(users.addUser)
.get(users.getAllUser)

userRouter.route('/:id')
.put(users.updateUser)
.delete(users.deleteUser)
.patch(users.changeUserPassword)



export default userRouter