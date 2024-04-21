import {Schema,model} from "mongoose";



const otpSchema=new Schema({
   
    phone:{
        type:String,
        unique:true,
        required:true,
    },
    otp:{
        type:String,
       require:true
    },
    createdAT:{type:Date,default:Date.now,index:{expires:300}}
})

export const otpModel=model('otp',otpSchema)
