import {
  Body,
  Controller,
  Get,
  Post,
  Req,
  Res,
  ValidationPipe,
} from '@nestjs/common';
import { LoginDTO, ResetPasswordDTO, SignupDTO } from './dtos/authDetails.dto';
import { UserService } from './user.service';
import { Response, Request } from 'express';
import { ERole } from 'src/master/schema/roleMaster.schema';
import { UpdateUserProfileInterface } from 'src/interfaces/auth.interface';

@Controller('user')
export class UserController {
  /**
   *
   */
  constructor(private userService: UserService) {}
  @Post('/signup')
  async signup(@Body(new ValidationPipe()) body: SignupDTO) {
    return await this.userService.registerService(body);
  }
  @Post('/login')
  async login(
    @Body(new ValidationPipe()) body: LoginDTO,
    @Res() response: Response,
  ) {
    const res = await this.userService.loginService(body, response);
    console.log('res: ', res);

    return response.status(200).json(res);
  }
  @Post('/forgotpassword')
  async forgotPassword(
    @Body() { role_id, email_id }: { email_id: string; role_id: ERole },
  ) {
    return await this.userService.forgotPasswordService(email_id, role_id);
  }
  @Post('/resetpassword')
  async resetPassword(@Body(new ValidationPipe()) body: ResetPasswordDTO) {
    return await this.userService.resetPassword(
      body.email_id,
      body.code,
      body.password,
      body.role_id,
    );
  }
  @Post('/changeemailrequest')
  async changeEmailRequest(@Body() body: { email: string; userRole: string }) {
    return await this.userService.changeEmailRequestService(
      body.email,
      body.userRole,
    );
  }
  @Post('/validateemailrequest')
  async validateEmailRequest(
    @Body() body: { email: string; userRole: string },
  ) {
    return await this.userService.validateEmailRequestService(
      body.email,
      body.userRole,
    );
  }
  @Post('/validateemail')
  async validateEmail(
    @Body() body: { email: string; userRole: string; code: string },
  ) {
    return await this.userService.validateEmailService(
      body.email,
      body.userRole,
      body.code,
    );
  }
  @Get('/refreshtoken')
  async updateAccessTokenService(@Req() request, @Res() response) {
    const userId = request?.user?._id || '';
    const res = await this.userService.updateAccessTokenService(
      userId,
      response,
    );
    return response.status(200).json(res);
  }
  @Get('/checktoken')
  async checkToken(@Req() request) {
    const userId = request?.user?._id || '';
    return await this.userService.getUserByTokenService(userId);
  }
  @Post('/sociallogin')
  async socialLogin(
    @Body(new ValidationPipe()) body: SignupDTO,
    @Res() response: Response,
  ) {
    const res = await this.userService.socialLoginService(body, response);
    return response.status(200).json(res);
  }
  @Post('/updateprofile')
  async updateUser(
    @Body() body: UpdateUserProfileInterface,
    @Req() request: any,
  ) {
    const userId = request?.user?._id || '';
    return await this.userService.updateUserProfileService(body, userId);
  }

  @Post('getuserbyemail')
  async getUserByEmail(@Body() body: { email_id: string; role_id: string }) {
    return await this.userService.getUserByEmail({
      email_id: body.email_id,
      role_id: body.role_id,
    });
  }
  @Get('verifyemaillink')
  async verifyEmail(@Req() request: any) {
    const email: string = request.user.email || '';
    return await this.userService.verifyEmailForLinkAccount(email);
  }
}
