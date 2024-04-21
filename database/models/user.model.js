import {Schema,model} from "mongoose";
import bcrypt from "bcrypt"
import jwt from 'jsonwebtoken'


const userSchema=new Schema({
    name:{
        type:String,
        required:true,
        trim:true,
    },

    email:{
        type:String,
        unique:true,
        required:true,
        trim:true,
        
    },
    password:{
        type:String,
        require:true

    },
    role:{
        type:String,
        enum:['admin','user'],
    },
    isActive:{
        type:Boolean,
        default:true
    },
    verified:{
        type:Boolean,
        default:false
    },
    blocked:{
        type:Boolean,
        default:false
    },
    phone:{
        type:String,
        unique:true,
        required:true,
    },
    gender:{
        type:String,
        enum:['male','female'],
    }
},{timestamps:true})


userSchema.methods.generateJWT=()=>{
    const token=jwt.sign({
        _id:this._id,
        phone:this.phone
    },process.env.JWT_SECRET_KEY,{expiresIn:"7d"})
    return token
}

userSchema.pre('save',function(){
  
    this.password=bcrypt.hashSync(this.password,8)
})

userSchema.pre('findOneAndUpdate',function(){
  
    if(this._update.password)this._update.password=bcrypt.hashSync( this._update.password,8)
})

export const userModel=model('user',userSchema)
