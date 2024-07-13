import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import {
  RoleMasterDocument,
  RoleMasterSchema,
} from './schema/roleMaster.schema';

@Injectable()
export class MasterService {
  constructor(
    @InjectModel(RoleMasterSchema.name)
    private roleMasterSchema: Model<RoleMasterDocument>,
  ) {}
  /***
   * Get All User Role of this application
   * @returns
   * @memberof MasterService
   **/
  async getAllUserRole() {
    return await this.roleMasterSchema.find();
  }
}
