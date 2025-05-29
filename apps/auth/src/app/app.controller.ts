import {
  Body,
  Controller,
  HttpStatus,
  Get,
  Post,
  Req,
  Res,
  UseGuards,
  UnauthorizedException,
  Param, BadRequestException
} from '@nestjs/common';
import { AppService } from './app.service';
import { IUser } from '@velogo/shared-interfaces';
import { CreateUserDTO } from './dto/create-user.dto';
import {Response} from 'express'
import { JwtAuthGuard } from '@velogo/authConf';

import { makeCookies } from '../utils/cookie.util';
import { OtpServiceService } from '../otp-service/otp-service.service';

type Flow = 'signup' | 'login' | 'forgot-password';
interface VerifyOtpDto {
  email: string;
  otp: string;
  password?: string;          // only used for forgot-password
}

@Controller()
export class AppController {
constructor(
  private readonly appService: AppService,
  private readonly otpService: OtpServiceService,
) {}

  @Post('signup/request-otp')
 async signup(@Res({passthrough:true}) res:Response, @Body() req:CreateUserDTO) {
      await this.appService.signup(req);
      res.status(HttpStatus.CREATED).json({success:true,message:"sent otp to your email!"})
  }
  @Post('login/request-otp')
  async login(@Res({passthrough:true}) res: Response, @Body() req:{email:string,password:string}) {
    await this.appService.login(req);
    res.status(HttpStatus.OK).json({success:true,message:"sent otp to your email!"})
  }
  @Post(':flow(signup|login|forgot-password)/verify-otp')
  async verifyOtp(
    @Param('flow') flow: Flow,
    @Res({ passthrough: true }) res: Response,
    @Body() req: VerifyOtpDto,
  ) {
    // If this is a forgot-password flow, ensure a new password was provided
    if (flow === 'forgot-password' && !req.password) {
      throw new BadRequestException('New password is required for password reset.');
    }
    let message: string;

    if (flow === 'forgot-password') {
      // Validate OTP & reset the password (no tokens issued)
      await this.appService.validate(req);
      message = 'Password reset successful!';
    } else {
      // signup or login: validate OTP and issue tokens
      const { authToken, refreshToken } = await this.appService.validate(req);
      makeCookies(res, authToken, refreshToken);
      message = flow === 'signup' ? 'Signup successful!' : 'Login successful!';
    }
    return res.status(HttpStatus.OK).json({ success: true, message });
  }
  @Post('refresh')
  async refresh(@Res({passthrough:true}) res:Response, @Req() req: Request & {cookies?:{'refreshToken':string}}){
    const refreshTo =  req.cookies.refreshToken
    if(!refreshTo) throw new UnauthorizedException("No Refresh Token found!")
   const {authToken, refreshToken} = await this.appService.refreshToken(refreshTo);
    makeCookies(res, authToken, refreshToken);
    res.status(HttpStatus.OK).json({success:true, info: "Refresh and Access tokens set successfully!"})
  }
  @UseGuards(JwtAuthGuard)
  @Get('')
  async getUser(@Req() req: Request & {user?:IUser}, @Res() res:Response){
    //TODO: add type to req
    const {_id} = req.user as {_id:string}
    const user = await this.appService.getUser(_id);
    res.status(HttpStatus.OK).json({success:true, user:user});
  }

  @Post('forgot-password')
  async forgotPassword(@Body() req:{email:string,password:string}, @Res() res: Response){
    await this.appService.forgot(req);
    res.status(HttpStatus.OK).json({success:true, message:"sent otp to your email!"})
  }
}
