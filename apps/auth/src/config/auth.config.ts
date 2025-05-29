import * as dotenv from 'dotenv';
dotenv.config();

export const authConfig = ()=> {
  return {
    port: 3000,
    twilio_sid:process.env.TWILIO_SID,
    twilio_token:process.env.TWILIO_TOKEN,
    twilio_from:"(320) 399-3295"
  }
}
