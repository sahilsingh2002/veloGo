import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ObjectId } from 'mongoose';
import { sharedConfig } from "@velogo/shared-config";
const config = sharedConfig()

const cookieExtractor = (req: Request & {cookies?:{'token':string}}) => {
    let token = null;
    if (req && req.cookies) {
      token = req.cookies['token'];
    }
    return token;
  };
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
    constructor() {
        super({
            jwtFromRequest: cookieExtractor,
            ignoreExpiration: false,
            secretOrKey: config.publicKey,
            algorithms: ['RS256']
        });
    }

    async validate(payload: {_id:string,iat:number,exp:number}) {
        console.log("Validating", payload)
        return payload;
    }
}