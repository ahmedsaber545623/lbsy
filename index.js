import express from 'express'
import { dbConnection } from './database/dbconnection.js'
import { bootstrap } from './src/bootstrab.js'
import otpGenerator from 'otp-generator';
import twilio from 'twilio';
import cors from 'cors'
import dotenv from "dotenv" 
dotenv.config()
const app =express()
const port =3001
app.use(express.json())
app.use(express.urlencoded({extended:false}))
app.use(cors())

bootstrap(app)
dbConnection()



app.listen(port,()=> console.log(`example app listening on port ${port}!`))
