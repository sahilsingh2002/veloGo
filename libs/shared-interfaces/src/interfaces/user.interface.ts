import { Document } from "mongoose";
export interface IUser extends Document{
    readonly firstName:string
    readonly lastName:string
    readonly email:string
    password:string
    readonly phone:string //for +91
    readonly age:number
    readonly role: "RIDER" | "DRIVER" | "ADMIN"
}
