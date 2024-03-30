import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { RoleCollection, RoleMasterSchema } from './schema/roleMaster.schema';

@Module({
  imports: [
    MongooseModule.forFeature([
      {
        name: RoleMasterSchema.name,
        schema: RoleCollection,
      },
    ]),
  ],
})
export class MasterModule {}
