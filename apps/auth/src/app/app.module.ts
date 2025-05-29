import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { MongooseModule } from '@nestjs/mongoose';
import {sharedConfig} from '@velogo/shared-config';
import {UserSchema} from '@velogo/shared-schema';
import { UserRepository } from '@velogo/shared-repositories';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { JwtStrategy } from '@velogo/authConf';
import { RefreshTokenSchema } from '../schema/refreshtoken.schema';
import { OtpSchema } from '../schema/otp.schema';
import { OtpServiceService } from '../otp-service/otp-service.service';
const config = sharedConfig()
@Module({

  imports: [MongooseModule.forRoot(config.db_url,{dbName:'veloGo'}),
    MongooseModule.forFeature([{name:"User", schema:UserSchema}, {name:"RefreshToken", schema:RefreshTokenSchema}, {name:"Otp", schema:OtpSchema}]),
    PassportModule,
    JwtModule.register({
        secret: config.privateKey, // Use environment variable for production
        signOptions: { expiresIn: '3m', algorithm: 'RS256' },
    }),
  ],
  controllers: [AppController],
  providers: [AppService, OtpServiceService, UserRepository, JwtStrategy],
  exports: [UserRepository]
})
export class AppModule {}
