import  {userModel}  from "../../database/models/user.model.js"
import {otpModel} from '../../database/models/OtpModel.js'
import jwt from "jsonwebtoken"
import _ from "lodash"
import axios from "axios"
import bcrypt from 'bcrypt'
import otpGenerator from 'otp-generator'





const catchError=(fn)=>{
    return (req,res,next)=>{
        fn(req,res,next).catch((err)=>{
            res.json(err)
        })
    }
}

const getAllUserSignIn=catchError(async(req,res)=>{
    
    let user=await userModel.find()
     res.status(201).json({message:"success",user})
 });

 const signUp=catchError(async(req,res,next)=>{
    let isUser=await userModel.findOne({email:req.body.email})
    if(isUser)return res.status(409).json({message:"already exists"})
    const user=new userModel(req.body)
    const OTP=otpGenerator.generate(6,{digits:true,alphabets:false,upperCase:false,specialChars:false})
    const phone=req.body.phone
    console.log(OTP);
    const otp =new otpModel({phone:phone,otp:OTP})
    const salt=await bcrypt.genSalt(10)
    otp.otp=await bcrypt.hash(otp.otp,salt)
    const result=await otp.save();

    await user.save()
    let token=jwt.sign({email:user.email,name:user.name,id:user._id,role:user.role},'khalid')
   

   
res.status(201).json({message:"success",token,user,result})

})

const verifyOtp=catchError(async(req,res,next)=>{
    const otpHolder=await otpModel.find({
        phone:req.body.phone
    })
    if(otpHolder.length==0)return res.status(400).json({message:"you use an expired otp"})
    const rightOtpFind=otpHolder[otpHolder.length - 1];
const validUser= await bcrypt.compare(req.body.otp, rightOtpFind.otp);

if(rightOtpFind.phone==req.body.phone&&validUser){
    const user=new userModel(_.pick(req.body,["phone"]))
    const token=user.generateJWT();
    const result=await user.save()
    
    return res.status(200).json({message:"user registeration successful"})
}else{
    return res.status(400).json({message:"your otp is wrong"})
}
   
})


const signIn=catchError(async(req,res,next)=>{
    const {email,password}=req.body
    let user=await userModel.findOne({email:req.body.email})

    if(user && bcrypt.compareSync(password,user.password)){
        let token=jwt.sign({email:user.email,name:user.name,id:user._id,role:user.role},'khalid')
        res.status(201).json({message:"success",token,email,password})
    }else{
        return res.status(409).json({message:"incorrect email or password"}) 
    }
   
})


 


export{
    signUp,
    signIn,
    getAllUserSignIn,
    verifyOtp
}