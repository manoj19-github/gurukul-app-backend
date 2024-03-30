import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { UserModule } from './user/user.module';
import { MasterModule } from './master/master.module';
import { JwtModule } from '@nestjs/jwt';
import { UtilsMain } from './utils.service';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
    }),
    JwtModule.register({
      global: true,
      secret: process.env.JWT_SECRET,
      signOptions: { expiresIn: process.env.JWT_ACCESS_TOKEN_EXPIRES },
    }),
    MongooseModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        uri: configService.get('DATABASE_URL'),
      }),
      inject: [ConfigService],
    }),
    UserModule,
    MasterModule,
  ],
  controllers: [AppController],
  providers: [AppService, UtilsMain],
  exports: [UtilsMain],
})
export class AppModule {}
