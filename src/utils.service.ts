import {
  AuthToken,
  GenerateAuthTokenInterface,
  GenerateAuthTokenResponse,
  ITokenOptions,
} from './interfaces/auth.interface';
import { createTransport, SendMailOptions } from 'nodemailer';
import * as moment from 'moment';
import { Response } from 'express';
import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ERole, RoleMasterSchema } from './master/schema/roleMaster.schema';

@Injectable()
export class UtilsMain {
  constructor(private jwtService: JwtService) {}
  validateEmail(email: string) {
    // tslint:disable-next-line:max-line-length
    const expression: RegExp =
      /^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    return expression.test(email);
  }
  async JWTSignup({
    res,
    email,
    role,
    _id,
  }: {
    res: Response;
    email: string;
    role: RoleMasterSchema;
    _id: any;
  }): Promise<AuthToken> {
    const accessTokenExpiresIn: any =
      process.env.JWT_ACCESS_TOKEN_EXPIRES || '3h';
    const refreshTokenExpiresIn: any =
      process.env.JWT_REFRESH_TOKEN_EXPIRES || '31d';

    const generateAuthTokenDetails = await this.generateAuthToken({
      email,
      role,
      _id,
      accessTokenExpiresIn,
      refreshTokenExpiresIn,
    });
    const accessTokenOptions: ITokenOptions = {
      expires: generateAuthTokenDetails.accessTokenExpiresDate,
      maxAge: generateAuthTokenDetails.accessTokenExpiresDate.getTime(),
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
    };
    const refreshTokenOptions: ITokenOptions = {
      expires: generateAuthTokenDetails.refreshTokenExpiresDate,
      maxAge: generateAuthTokenDetails.refreshTokenExpiresDate.getTime(),
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
    };
    res.cookie(
      'access_token',
      generateAuthTokenDetails.accessToken,
      accessTokenOptions,
    );
    res.cookie(
      'refresh_token',
      generateAuthTokenDetails.refreshToken,
      refreshTokenOptions,
    );
    // UPLOAD TOKEN TO REDIS
    return {
      accessToken: generateAuthTokenDetails.accessToken,
      refreshToken: generateAuthTokenDetails.refreshToken,
    };
  }

  sendMailMethod(mailOptions: SendMailOptions): Promise<boolean> {
    const transporter = createTransport({
      //@ts-ignore
      host: 'smtp.gmail.com',
      secureConnection: false, // TLS requires secureConnection to be false
      port: 465,
      secure: true,
      auth: {
        user: process.env.EMAIL_USERNAME,
        pass: process.env.EMAIL_PASSWORD,
      },
      tls: {
        rejectUnAuthorized: true,
      },
    });
    return new Promise((resolve, reject) => {
      transporter.sendMail(mailOptions, (error, _) => {
        if (error) return reject(false);
        return resolve(true);
      });
    });
  }
  async generateAuthToken({
    email,
    role,
    _id,
    accessTokenExpiresIn,
    refreshTokenExpiresIn,
  }: GenerateAuthTokenInterface): Promise<GenerateAuthTokenResponse> {
    const accessToken = await this.jwtService.signAsync(
      { email: email, role: role, _id: _id },
      {
        expiresIn: accessTokenExpiresIn,
      },
    );
    const refreshToken = await this.jwtService.signAsync(
      { email: email, role: role, _id: _id },
      {
        expiresIn: refreshTokenExpiresIn,
      },
    );
    const accessTimeDays = String(accessTokenExpiresIn)
      .split('')
      .filter((self) => Number.isInteger(Number(self)))
      .join('');
    const refreshTimeDays = String(refreshTokenExpiresIn)
      .split('')
      .filter((self) => Number.isInteger(Number(self)))
      .join('');
    const accessTokenExpiresDate = new Date(
      moment().add(accessTimeDays, 'minutes').format('YYYY-MM-DD HH:mm:ss'),
    );
    const refreshTokenExpiresDate = new Date(
      moment().add(refreshTimeDays, 'days').format('YYYY-MM-DD'),
    );

    return {
      accessToken,
      accessTokenExpiresDate,
      refreshToken,
      refreshTokenExpiresDate,
    };
  }
}
