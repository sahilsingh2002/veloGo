import * as dotenv from 'dotenv'
import * as fs from 'fs'
import * as path from 'path'

dotenv.config()
export function sharedConfig(): { db_url: string; privateKey: string; publicKey: string; nodemailer_auth: { user: string; pass: string; }; } {
  return {
    db_url: process.env.MONGODB_URI || '',
    privateKey: fs.readFileSync(
      path.join(process.cwd(), 'keys', 'rsa.key'),
      'utf8'
    ),
    publicKey: fs.readFileSync(
      path.join(process.cwd(), 'keys', 'rsa.key.pub'),
      'utf8'
    ),
    nodemailer_auth: {
      user: 'ss2202002@gmail.com',
      pass: 'ooutwtxyibkdghyw',
    },
  };
}
