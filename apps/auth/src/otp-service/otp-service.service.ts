import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { Twilio } from 'twilio';
import * as nodemailer from 'nodemailer';
import { InjectModel } from '@nestjs/mongoose';
import { Otp } from '../schema/otp.schema';
import { IOtp } from '../interfaces/otp.interface';
import { User } from '@velogo/shared-schema';
import { IUser } from '@velogo/shared-interfaces';
import {authConfig} from '../config/auth.config';
import { Model } from 'mongoose';
import { sharedConfig } from '@velogo/shared-config';

@Injectable()
export class OtpServiceService {
  private twilioClient:Twilio;
  private mailer: nodemailer.Transporter;
  private config = authConfig(); // just like sharedConfig()
  private mainConf = sharedConfig();
  constructor(
    @InjectModel(Otp.name) private otpModel: Model<IOtp>,
    @InjectModel(User.name) private userModel: Model<IUser>,
  ) {
    this.twilioClient = new Twilio(
      this.config.twilio_sid,
      this.config.twilio_token,
    );
    this.mailer = nodemailer.createTransport({
      service: 'gmail',
      auth: this.mainConf.nodemailer_auth,
    });
  }
  private generateOtp():string{
    return Math.floor(10**6 + Math.random()*9*10**5).toString()
  }
  async sendOtp(user:IUser):Promise<boolean>{
    try {
      console.log(user._id)
      await this.otpModel.deleteMany({ userId:user._id })
      const otp = this.generateOtp();
      const expiresAt = new Date(Date.now() + 5*60*1000);
      await this.otpModel.create({
        otp,
        expiresAt,
        userId:user._id
      })
      // await this.twilioClient.messages.create({
      //   body: `Your OTP is ${otp}. This OTP expires in 5 minutes.`,
      //   from: this.config.twilio_from,
      //   to: "+91"+user.phone,
      // })
      await this.mailer.sendMail({
        to: user.email,
        from: this.mainConf.nodemailer_auth.user,
        subject: "OTP Code",
        html: `Your OTP is ${otp}. This OTP expires in 5 minutes.`
      })

      return true;
    }
    catch(e){
      console.log(e.message)
      return false;
    }
  }
  async validateOtp(user:IUser, otp:string, password?:string):Promise<boolean>{
    const userRec = await this.otpModel.findOne({ otp, userId: user._id, expiresAt: { $gt: new Date() } })
    if(userRec.userId.toString() !== user._id.toString()) return false
    if(password){
     const userEntry = await this.userModel.findOne({_id:user._id})
      userEntry.password = password;
     await userEntry.save();
    }
    return true
  }
}
