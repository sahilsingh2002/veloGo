import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';
import { User } from '@velogo/shared-schema';

@Schema({ timestamps: true})
export class Otp extends Document{
  @Prop({required:true, index:true})
  otp:string;

  @Prop({required:true})
  expiresAt:Date;

  @Prop({type:Types.ObjectId, ref: User.name, required:true})
  userId: string;
}

export const OtpSchema = SchemaFactory.createForClass(Otp);

// **Add this** right after creating the Schema:
OtpSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
