/* eslint-disable @typescript-eslint/no-this-alias */
/* eslint-disable @typescript-eslint/no-unused-vars */
import { Schema, Prop, SchemaFactory } from '@nestjs/mongoose';
import { Types } from 'mongoose';
import { RoleMasterSchema } from 'src/master/schema/roleMaster.schema';
import * as bcrypt from 'bcrypt';

import validator from 'validator';

export type UserSchemaDocument = UserSchema & Document;
export interface TokenVerification {
  token: string;
  expiration: Date;
}
@Schema({ timestamps: true, collection: 'user' })
export class UserSchema {
  @Prop({ required: [true, 'user name is required'] })
  user_name: string;
  @Prop({
    type: Types.ObjectId,
    ref: RoleMasterSchema.name,
    required: [true, 'role id is required'],
  })
  role_id: RoleMasterSchema; // to do
  @Prop({ required: [true, 'password is required'] })
  password: string;
  @Prop({
    type: Types.ObjectId,
    ref: 'AddressSchema',
    required: false,
  })
  address_id: Types.ObjectId; // to do
  @Prop({
    type: String,
    required: [true, 'email is required'],
    validate: {
      validator: (value) => validator.isEmail(value),
      message: 'Email is not valid',
    },
  })
  email_id: string;
  @Prop({
    type: String,
    required: false,
  })
  phone_number?: string;
  @Prop({
    type: Boolean,
    default: false,
  })
  is_email_verified: boolean;
  @Prop({
    type: String,
    default: '',
  })
  avatar: string;
  @Prop({
    type: {
      token: String,
      expiration: Date,
    },
    default: null,
  })
  reset_password_verification: TokenVerification;
  @Prop({
    type: {
      token: String,
      expiration: Date,
    },
    default: null,
  })
  email_verification: TokenVerification;
  @Prop({
    type: {
      token: String,
      expiration: Date,
    },
    default: null,
  })
  reset_email_verification: TokenVerification;
  @Prop({
    type: Boolean,
    default: false,
  })
  is_registered: boolean;
  @Prop({
    type: Boolean,
    default: false,
  })
  enabled: boolean;
}

export const UserCollection = SchemaFactory.createForClass(UserSchema);
