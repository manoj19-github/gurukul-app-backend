import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { randomBytes } from 'crypto';
import { SendMailOptions } from 'nodemailer';
import { UtilsMain } from '../utils.service';

import { Response } from 'express';

import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import { UserSchema, UserSchemaDocument } from './schema/user.schema';
import { ERole } from 'src/master/schema/roleMaster.schema';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { LoginDTO, SignupDTO } from './dtos/authDetails.dto';
import {
  UpdateAuthToken,
  ITokenOptions,
  UpdateUserProfileInterface,
} from 'src/interfaces/auth.interface';

@Injectable()
export class UserService {
  constructor(
    private jwtService: JwtService,
    private utilsService: UtilsMain,
    @InjectModel(UserSchema.name) private UserModel: Model<UserSchemaDocument>,
  ) {}
  /***
   * Register service of user
   * @param {string} usertype
   * @returns
   * @memberof UserService
   **/

  async registerService(
    body: SignupDTO,
    // opts: { session: ClientSession }
  ) {
    const isEmailExists = await this.UserModel.findOne({
      email: body.email_id,
      role_id: body.role_id,
    });
    //  email duplication check
    if (!!isEmailExists) return isEmailExists;
    // const newRegistrationUser = await new UserModel({ name, email, password, avatar, userRole, isRegistered: true }).save(opts);
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(body.password, salt);
    const newRegistrationUser = await this.UserModel.create({
      user_name: body.user_name,
      role_id: body.role_id,
      password: hashedPassword,
      email_id: body.email_id,
    });
    const mailOptions: SendMailOptions = {
      from: process.env.EMAIL_USERNAME!,
      to: body.email_id,
      subject: `Welcome To Gurukul`,
      html: `

              <h1 style="text-align:center">GuruKul</h1>
              <p style="text-align:center"> <small>Your Future, Our Commitment</small></p>
              <p></p>
              <p></p>
              <p></p>
              <p style="text-align:justify">Hi ${body.user_name}, Welcome to Gurukul
              </p>
              <p style="text-align:justify">Your login Email : ${body.email_id}</p>
              <p style="text-align:justify"> Your password is :  ${body.password}</p>
      `,
    };
    try {
      await this.utilsService.sendMailMethod(mailOptions);
    } catch (error) {
      console.log('error : ', error);
    }
    return newRegistrationUser;
  }

  /***
   * Login service of user
   * @param {string} email
   * @param {string} password
   * @param {string} role_id
   * @param {Response} res
   * @memberof UserService
   **/
  async loginService(body: LoginDTO, res: Response) {
    const isUserExists = await this.UserModel.findOne({
      email_id: body.email_id,
      role_id: body.role_id,
    });
    if (!isUserExists)
      throw new HttpException('Email not exists', HttpStatus.BAD_REQUEST);
    console.log('body password : ', body.password);
    console.log('user password : ', isUserExists.password);
    const passwordValid = await bcrypt.compare(
      body.password,
      isUserExists.password,
    );
    console.log('passwordValid : ', passwordValid);
    if (!!passwordValid) {
      const userToken = await this.utilsService.JWTSignup({
        res,
        email: isUserExists.email_id,
        role: isUserExists.role_id,
        _id: isUserExists._id,
      });

      let userDetails: any = JSON.parse(JSON.stringify(isUserExists));
      delete userDetails.password;

      return { token: userToken, user: userDetails };
    } else
      throw new HttpException('password not valid', HttpStatus.BAD_REQUEST);
  }
  /***
   * forgot password service
   * @param {string} email
   * @param {string} password
   * @param {string} userRole
   * @memberof UserService
   **/
  async forgotPasswordService(
    email: string,
    userRole: string,
  ): Promise<boolean> {
    const isUserExists = await this.UserModel.findOne({
      email_id: email,
      role_id: userRole,
    });
    if (!isUserExists)
      throw new HttpException('user not  exists', HttpStatus.BAD_REQUEST);
    const expiresIn: any = process.env.JWT_ACCESS_TOKEN_EXPIRES;
    const expiration = new Date();
    expiration.setTime(expiration.getTime() + expiresIn * 1000);
    const token = randomBytes(3).toString('hex');
    const mailOptions: SendMailOptions = {
      from: process.env.EMAIL_USERNAME!,
      to: email,
      subject: `Welcome To Gurukul`,
      html: `

              <h1 style="text-align:center">GuruKul</h1>
              <p style="text-align:center"> <small>Your Future, Our Commitment</small></p>
              <p></p>
              <p></p>
              <p></p>
              <p style="text-align:center">${isUserExists.user_name}, Replace your password with this : ${token} <br/><small> please note this token is invalid after 24 hours of generate</small> </p>
      `,
    };
    return new Promise((resolve, reject) => {
      return this.utilsService
        .sendMailMethod(mailOptions)
        .then((res) => {
          this.UserModel.updateOne(
            { _id: isUserExists._id },
            { $set: { resetPasswordVerification: { token, expiration } } },
          )
            .then(() => resolve(true))
            .catch(() => reject(false));
        })
        .catch(() => reject(false));
    });
  }
  /***
   * reset password service
   * @param {string} email
   * @param {string} code
   * @param {string} password
   * @param {string} userRole
   * @memberof UserService
   **/
  async resetPassword(
    email_id: string,
    code: string,
    password: string,
    role_id: string,
  ): Promise<boolean> {
    const userDetails = await this.UserModel.findOne({
      email_id: email_id,
      role_id: role_id,
    });
    if (
      !!userDetails &&
      userDetails?.reset_password_verification &&
      userDetails.enabled !== false
    ) {
      if (
        new Date().getTime() >
        new Date(userDetails.reset_password_verification.expiration).getTime()
      )
        throw new HttpException('token expired', HttpStatus.BAD_REQUEST);
      if (userDetails.reset_password_verification.token === code) {
        await this.UserModel.updateOne(
          { _id: userDetails._id },
          { $set: { password, resetPasswordVerification: undefined } },
        );
        return true;
      } else throw new HttpException('invalid token', HttpStatus.BAD_REQUEST);
    }
    return false;
  }
  /***
   * change email request service
   * @param {string} email
   * @param {string} userRole
   * @memberof UserService
   **/
  async changeEmailRequestService(
    email: string,
    userRole: string,
  ): Promise<boolean> {
    const isUserExists = await this.UserModel.findOne({
      email_id: email,
      role_id: userRole,
    });
    if (!isUserExists)
      throw new HttpException('user not  exists', HttpStatus.BAD_REQUEST);
    const expiresIn: any = process.env.JWT_ACCESS_TOKEN_EXPIRES;
    const expiration = new Date();
    expiration.setTime(expiration.getTime() + expiresIn * 1000);
    const token = randomBytes(3).toString('hex');
    const mailOptions: SendMailOptions = {
      from: process.env.EMAIL_USERNAME!,
      to: email,
      subject: `Change Email Request`,
      html: `

              <h1 style="text-align:center">GuruKul</h1>
              <p style="text-align:center"> <small>Your Future, Our Commitment</small></p>
              <p></p>
              <p></p>
              <p></p>
              <p style="text-align:center">${isUserExists.user_name}, Replace your password with this : ${token} <br/><small> please note this token is invalid after 24 hours of generate</small> </p>
      `,
    };
    return new Promise((resolve, reject) => {
      return this.utilsService
        .sendMailMethod(mailOptions)
        .then((res) => {
          this.UserModel.updateOne(
            { _id: isUserExists._id },
            { $set: { resetEmailVerification: { token, expiration } } },
          )
            .then(() => resolve(true))
            .catch(() => reject(false));
        })
        .catch(() => reject(false));
    });
  }
  /***
   * reset email service
   * @param {string} email
   * @param {string} userRole
   * @returns {Promise<boolean>}
   * @memberof UserService
   **/
  async resetEmailRequest(
    oldEmail: string,
    code: string,
    newEmail: string,
    userRole: string,
  ): Promise<boolean> {
    const userDetails = await this.UserModel.findOne({
      email_id: oldEmail,
      role_id: userRole,
    });
    if (
      !!userDetails &&
      userDetails?.reset_email_verification &&
      userDetails.enabled !== false
    ) {
      if (
        new Date().getTime() >
        new Date(userDetails.reset_email_verification.expiration).getTime()
      )
        throw new HttpException('token expired', HttpStatus.BAD_REQUEST);
      if (userDetails.reset_email_verification.token === code) {
        await this.UserModel.updateOne(
          { _id: userDetails._id },
          { $set: { email: newEmail, resetEmailVerification: undefined } },
        );
        return true;
      } else throw new HttpException('invalid token', HttpStatus.BAD_REQUEST);
    }
    return false;
  }
  /***
   * validate  email request service
   * @param {string} email
   * @param {string} userRole
   * @returns {Promise<boolean>}
   * @memberof UserService
   **/
  async validateEmailRequestService(
    email: string,
    userRole: string,
  ): Promise<boolean> {
    const token = randomBytes(3).toString('hex');
    const isUserExists = await this.UserModel.findOne({
      email_id: email,
      role_id: userRole,
    }).select('-password');
    if (!isUserExists)
      throw new HttpException('Email is not found', HttpStatus.BAD_REQUEST);
    const expiresIn: any = process.env.JWT_ACCESS_TOKEN_EXPIRES;
    const expiration = new Date();
    expiration.setTime(expiration.getTime() + expiresIn * 1000);
    const mailOptions: SendMailOptions = {
      from: process.env.EMAIL_USERNAME!,
      to: email,
      subject: `Validate Email Request`,
      html: `

              <h1 style="text-align:center">GuruKul</h1>
              <p style="text-align:center"> <small>Your Future, Our Commitment</small></p>
              <p></p>
              <p></p>
              <p></p>
              <p style="text-align:center">${isUserExists.user_name}, Validate your password with this : ${token} <br/><small> please note this token is invalid after 24 hours of generate</small> </p>
      `,
    };
    return new Promise((resolve, reject) => {
      return this.utilsService
        .sendMailMethod(mailOptions)
        .then((res) => {
          this.UserModel.updateOne(
            { _id: isUserExists._id },
            { $set: { emailVerication: { token, expiration } } },
          )
            .then(() => resolve(true))
            .catch(() => reject(false));
        })
        .catch(() => reject(false));
    });
  }

  /***
   * validate email service
   * @param {string} email
   * @param {string} userRole
   * @param {string} code
   * @returns {Promise<boolean>}
   * @memberof UserService
   **/
  async validateEmailService(
    email: string,
    userRole: string,
    code: string,
  ): Promise<boolean> {
    const isUserExists = await this.UserModel.findOne({
      email_id: email,
      role_id: userRole,
    }).select('-password');
    if (!isUserExists)
      throw new HttpException('Email is not found', HttpStatus.BAD_REQUEST);
    if (
      !!isUserExists &&
      isUserExists?.email_verification &&
      isUserExists.enabled !== false
    ) {
      if (
        new Date().getTime() >
        new Date(isUserExists.email_verification.expiration).getTime()
      )
        throw new HttpException('token expired', HttpStatus.BAD_REQUEST);
      if (isUserExists.email_verification.token === code) {
        await this.UserModel.updateOne(
          { _id: isUserExists._id },
          { $set: { email_verification: undefined, is_email_verified: true } },
        );
        return true;
      } else throw new HttpException('invalid token', HttpStatus.BAD_REQUEST);
    }
    return false;
  }
  /***
   * update access token
   * @param {string} refreshToken
   * @param {Response} res
   * @returns {Promise<UpdateAuthToken>}
   * @memberof UserService
   **/
  async updateAccessTokenService(
    userId: string,
    res: Response,
  ): Promise<UpdateAuthToken> {
    // const decoded = (await this.jwtService.verifyAsync(refreshToken, {
    //   secret: String(process.env.JWT_SECRET),
    // })) as AuthJWTPayload;
    // if (!decoded)
    //   throw new HttpException(
    //     'Refresh token is not valid',
    //     HttpStatus.BAD_REQUEST,
    //   );
    // const userSession = await redis.get(decoded._id);
    const userDetails = await this.UserModel.findById(userId);

    if (!userDetails)
      throw new HttpException(
        'Refresh token is not valid',
        HttpStatus.BAD_REQUEST,
      );
    const accessTokenExpiresIn: any =
      process.env.JWT_ACCESS_TOKEN_EXPIRES || '5m';
    const refreshTokenExpiresIn: any =
      process.env.JWT_REFRESH_TOKEN_EXPIRES || '31d';
    const generateAuthTokenDetails = await this.utilsService.generateAuthToken({
      email: userDetails.email_id,
      role: userDetails.role_id,
      _id: userDetails._id as any,
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
    // UPLOAD SESSION TO REDIS
    // await redis.set(
    //   decoded._id,
    //   JSON.stringify({ email: userDetails.email, role: userDetails.role }),
    // );
    return {
      accessToken: generateAuthTokenDetails.accessToken,
      refreshToken: generateAuthTokenDetails.refreshToken,
      userId,
    };
  }

  /***
   * get logged in user details by auth token
   * @param {string} userId
   * @returns {Promise<IUserSchema | undefined>}
   * @memberof UserService
   **/
  async getUserByTokenService(userId: string) {
    return await this.UserModel.findById(userId).select('-password');
  }

  /***
   * social login service
   * @param {string} name
   * @param {string} email
   * @param {string} password
   * @param {string} avatar
   * @param {string} userRole
   * @param {Response} res
   * @param {{ session: ClientSession }} opts
   * @returns {Promise<IUserSchema | undefined>}
   * @memberof UserService
   **/
  async socialLoginService(
    body: SignupDTO,
    res: Response,
    // opts: { session: ClientSession }
  ) {
    const isEmailExists = await this.UserModel.findOne({
      email_id: body.email_id,
      role_id: body.role_id,
    });
    if (!isEmailExists) await this.registerService(body);
    return await this.loginService(body, res);
  }
  // registerService(
  //   name: string,
  //   email: string,
  //   password: string,
  //   userRole: ERole,
  // ) {
  //   throw new Error('Method not implemented.');
  // }
  // loginService(
  //   email: string,
  //   password: string,
  //   userRole: string,
  //   res: Response<any, Record<string, any>>,
  // ) {
  //   throw new Error('Method not implemented.');
  // }

  /***
   * update user profile service
   * @param {UpdateUserProfileInterface} userDetails
   * @param {string} userId
   * @returns {Promise<IUserSchema | undefined>}
   * @memberof UserService
   **/

  async updateUserProfileService(
    userDetails: UpdateUserProfileInterface,
    userId: string,
  ) {
    if (userId.trim().length === 0)
      throw new HttpException('user id not found', HttpStatus.BAD_REQUEST);
    if (!userDetails || Object.keys(userDetails).length === 0)
      throw new HttpException(
        'updatable details not found',
        HttpStatus.BAD_REQUEST,
      );
    const updatedUserDetails = await this.UserModel.findOneAndUpdate(
      { _id: userId },
      { $set: { ...userDetails } },
      { returnDocument: 'after' },
    );
    // await redis.set(
    //   userId,
    //   JSON.stringify({
    //     email: updatedUserDetails?.email,
    //     role: updatedUserDetails?.userRole,
    //   }),
    // );
    return updatedUserDetails;
  }

  /***
   * get user by user email
   * @param {string} userEmail
   * @param {string} userRole
   * @returns {Promise<IUserSchema | undefined>}
   * @memberof UserService
   **/
  async getUserByEmail({
    email_id,
    role_id,
  }: {
    email_id: string;
    role_id: string;
  }) {
    return await this.UserModel.findOne({
      email_id,
      role_id,
    });
  }
  /***
   * get user by user email
   * @param {string} userId
   * @returns {Promise<IUserSchema | undefined>}
   * @memberof UserService
   **/
  async verifyEmailForLinkAccount(email: string) {
    return await this.UserModel.updateOne(
      { email_id: email },
      { $set: { isEmailVerified: true } },
    );
  }
}
