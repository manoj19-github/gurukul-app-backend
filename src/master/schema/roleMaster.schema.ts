import { Schema, Prop, SchemaFactory } from '@nestjs/mongoose';

export enum ERole {
  STUDENT = 'STUDENT',
  INSTRUCTOR = 'INSTRUCTOR',
  INSTITUTION = 'INSTITUTION',
  ADMIN = 'ADMIN',
}
export type TAction = 'READ' | 'WRITE' | 'EDIT' | 'DELETE';
export type RoleMasterDocument = RoleMasterSchema & Document;
@Schema({ timestamps: true, collection: 'rolemaster' })
export class RoleMasterSchema {
  @Prop({ required: [true, 'role name is required'], default: ERole.STUDENT })
  role_name: ERole;
  @Prop({
    type: [
      { pageName: { type: String }, featureName: String, action: [String] },
    ],
  })
  access_control: Array<{
    pageName: string;
    featureName: string;
    action: Array<TAction>;
  }>;
}

export const RoleCollection = SchemaFactory.createForClass(RoleMasterSchema);
