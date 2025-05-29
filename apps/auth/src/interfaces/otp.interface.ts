import { Document } from 'mongoose';
export interface IOtp extends Document{
  readonly otp: string,
  readonly expiresAt: Date,
  readonly userId: string
}
