import { Injectable } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { Model } from "mongoose";
import { IUser } from '@velogo/shared-interfaces';

@Injectable()
export class UserRepository{
    constructor(@InjectModel('User') private userModel:Model<IUser>){ }
    async findByEmail(email:string):Promise<IUser | null>{
        return this.userModel.findOne({email}).exec()
    }
    async findById(id:string): Promise<IUser | null>{
        return this.userModel.findById(id)
    }
}