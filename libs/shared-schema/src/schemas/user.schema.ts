import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import { Document } from "mongoose";
import * as bcrypt from 'bcrypt'

@Schema()
export class User extends Document{
    @Prop({required:true})
    firstName: string
    @Prop()
    lastName:string

    @Prop({required:true})
    email:string

    @Prop({required:true})
    password:string

    @Prop({required:true})
    phone:string

    @Prop({required:true})
    age:number

    @Prop({required:true})
    role: "RIDER" | "DRIVER" | "ADMIN"
}
export const UserSchema = SchemaFactory.createForClass(User);
UserSchema.pre('save', async function(next) {
    if (this.isModified('password')) {
      const saltRounds = 10;
      this.password = await bcrypt.hash(this.password, saltRounds);
    }
    next();
  });
