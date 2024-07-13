import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { RoleCollection, RoleMasterSchema } from './schema/roleMaster.schema';
import { MasterController } from './master.controller';
import { MasterService } from './master.service';

@Module({
  imports: [
    MongooseModule.forFeature([
      {
        name: RoleMasterSchema.name,
        schema: RoleCollection,
      },
    ]),
  ],
  controllers: [MasterController],
  providers: [MasterService],
  exports: [MasterService],
})
export class MasterModule {}
