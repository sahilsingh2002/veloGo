import { BadRequestException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import {IUser} from '@velogo/shared-interfaces'
import { CreateUserDTO } from './dto/create-user.dto';
import { UserRepository } from '@velogo/shared-repositories'
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt'
import { JwtService } from '@nestjs/jwt';
import { RefreshToken } from '../schema/refreshtoken.schema';
import { v4 as uuidv4 } from 'uuid';
import { randomBytes } from 'crypto';
import { OtpServiceService } from '../otp-service/otp-service.service';

@Injectable()
export class AppService {
  constructor(
    private readonly userRepository: UserRepository,
    @InjectModel('User') private readonly userModel: Model<IUser>,
    @InjectModel('RefreshToken') private refreshTokenModel: Model<RefreshToken>,
    private jwtService: JwtService,
    private otpService: OtpServiceService
  ) {}
  async signup(
    createUserDTO: CreateUserDTO
  ): Promise<{ authToken: string; refreshToken: string }> {
    try {
      const { email } = createUserDTO;
      const existingUser = await this.userRepository.findByEmail(email);
      // TODO: make new exception for this
      if (existingUser) throw new BadRequestException('User Already Exists!');
      const newUser = new this.userModel(createUserDTO);
      const user = await newUser.save();
      await this.otpService.sendOtp(user);
      return await this.generateTokens(user._id.toString());
    } catch (e) {
      throw new BadRequestException(e.message);
    }
  }
  async login(req: { email: string; password: string }): Promise<void> {
    const { email, password } = req;
    const user = await this.userRepository.findByEmail(email);
    if (!user) {
      throw new NotFoundException('Either Email or Password are wrong!');
    }
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      throw new NotFoundException('Incorrect Password!');
    }
    const sent = await this.otpService.sendOtp(user);
    if (!sent) throw new BadRequestException('Unable to send OTP!');
    return;
  }
  async forgot(req: { email:string }): Promise<void> {
    const { email } = req;
    const user = await this.userRepository.findByEmail(email);
    if (!user) throw new NotFoundException('User not found!');
    const sent = await this.otpService.sendOtp(user);
    if (!sent) throw new BadRequestException('Unable to send OTP!');
  }
  async validate(req: {
    email: string;
    otp: string;
    password?: string;
  }): Promise<{ authToken: string; refreshToken: string }> {
    const userData = await this.userRepository.findByEmail(req.email);
    if (!userData) throw new NotFoundException('User not found!');
    const match = await this.otpService.validateOtp(
      userData,
      req.otp,
      req.password
    );
    if (!match) throw new UnauthorizedException('Invalid OTP!');
    return await this.generateTokens(userData._id.toString());
  }
  async refreshToken(
    oldToken: string
  ): Promise<{ authToken: string; refreshToken: string }> {
    const tokenData = await this.refreshTokenModel.findOne({ token: oldToken });
    if (!tokenData || tokenData.expires < new Date())
      throw new UnauthorizedException(
        'Refresh Token expired! Pleas login again!'
      );
    await this.refreshTokenModel.findByIdAndDelete(tokenData._id);
    return await this.generateTokens(tokenData.userId.toString());
  }

  async getUser(userId: string) {
    const user = await this.userRepository.findById(userId);
    console.log(user);
    if (!user) throw new NotFoundException('Not found!');
    return user;
  }

  private async generateTokens(userId: string) {
    const refreshToken = randomBytes(64).toString('hex');
    const tokenIndex = uuidv4();
    const expires = new Date();
    expires.setDate(expires.getDate() + 7);

    await this.refreshTokenModel.create({
      userId: userId,
      token: refreshToken,
      expires,
      tokenIndex,
    });
    const authToken = this.jwtService.sign({ _id: userId });
    return { authToken, refreshToken };
  }
}
