import  {userModel}  from "../../../database/models/user.model.js"





const catchError=(fn)=>{
    return (req,res,next)=>{
        fn(req,res,next).catch((err)=>{
            res.json(err)
        })
    }
}


 const addUser=catchError(async(req,res,next)=>{

    const{name,email,password,phone,gender}=req.body
    
    const user=new userModel(req.body)
    await userModel.save()
    res.status(201).json({message:"success",user})
})

 const getAllUser=catchError(async(req,res)=>{
    
   let users=await userModel.find()
    res.status(201).json({message:"success",users})
});

const updateUser=catchError(async(req,res)=>{
    const{id}=req.params
    let user=await userModel.findByIdAndUpdate(id,req.body,{new:true})
    !user && res.status(404).json({message:"user not found"})
     user && res.status(201).json({message:"sucess",user})
 });


 const changeUserPassword=catchError(async(req,res)=>{
    const{id}=req.params
    let user=await userModel.findByIdAndUpdate(id,{password:req.body.password},{new:true})
    !user && res.status(404).json({message:"user not found"})
     user && res.status(201).json({message:"sucess",user})
 });

 const deleteUser=catchError(async(req,res)=>{
    const{id}=req.params
   
    let user=await userModel.findByIdAndDelete(id)
     !user && res.status(404).json({message:"user not found"})
     user && res.status(201).json({message:"sucess",user})
 });
 
 


export{
    addUser,
    getAllUser,
    updateUser,
    deleteUser,
    changeUserPassword
}