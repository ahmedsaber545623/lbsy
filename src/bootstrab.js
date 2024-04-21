import authRouter from "./auth/auth.routes.js"
import userRouter from "./modules/user/user.routes.js"



export function bootstrap(app){
    app.use('/api/v1/users',userRouter)
    app.use('/api/v1/auth',authRouter)
    app.get('/',(req,res)=>res.send('hello world'))
}