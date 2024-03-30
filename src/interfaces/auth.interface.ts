import { Request } from 'express';
import { JwtPayload } from 'jsonwebtoken';
import { ERole, RoleMasterSchema } from 'src/master/schema/roleMaster.schema';
export interface IUserBody {
  _id: string;
  email: string;
  role: ERole;
}

export interface RequestWithUser extends Request {
  user?: IUserBody;
  body: any;
  headers: any;
}

export interface AuthJWTPayload extends JwtPayload {
  _id: string;
  email: string;
  role: ERole;
}

export interface ITokenOptions {
  expires: Date;
  maxAge: number;
  httpOnly: boolean;
  sameSite: 'lax' | 'strict' | 'none' | undefined;
  secure?: boolean;
}

export interface AuthToken {
  accessToken: string;
  refreshToken: string;
}

export interface UpdateAuthToken extends AuthToken {
  userId: any;
}

export interface GenerateAuthTokenInterface {
  email: string;
  role: RoleMasterSchema;
  _id: string;
  refreshTokenExpiresIn: any;
  accessTokenExpiresIn: any;
}

export interface GenerateAuthTokenResponse {
  accessToken: string;
  accessTokenExpiresDate: Date;
  refreshToken: string;
  refreshTokenExpiresDate: Date;
}

export interface UpdateUserProfileInterface {
  avatar?: string;
  name?: string;
}
