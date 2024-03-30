import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { UserSchema, UserCollection } from './schema/user.schema';
import { UserController } from './user.controller';
import { UserService } from './user.service';
import { UtilsMain } from 'src/utils.service';

@Module({
  imports: [
    MongooseModule.forFeature([
      {
        name: UserSchema.name,
        schema: UserCollection,
      },
    ]),
  ],
  controllers: [UserController],
  providers: [UserService, UtilsMain],
})
export class UserModule {}
