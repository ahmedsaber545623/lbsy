import mongoose from "mongoose";




 export const   dbConnection=async()=>{
    return await mongoose.connect('mongodb+srv://khalidfawzi:010633728321MG@cluster0.3vzqf18.mongodb.net/ahmed').then((result)=>{
        console.log(" database connected")
    }).catch((err)=>{
        console.log("database erorr",err);
    })
}