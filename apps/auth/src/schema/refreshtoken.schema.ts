import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import { Document, Schema as sch } from "mongoose";

@Schema()
export class RefreshToken extends Document{
    @Prop({ type: sch.Types.ObjectId, ref: 'User', required: true })
    userId: sch.Types.ObjectId

    @Prop({required:true, unique:true})
    token:string

    @Prop({required:true})
    expires:Date

    @Prop({required:true})
    tokenIndex: string
}
export const RefreshTokenSchema = SchemaFactory.createForClass(RefreshToken);
RefreshTokenSchema.index({ expires: 1 }, { expireAfterSeconds: 0 });
RefreshTokenSchema.index({ tokenIndex: 1 });