import { Controller, Get, Req, Res } from '@nestjs/common';
import { MasterService } from './master.service';

@Controller('master')
export class MasterController {
  constructor(private masterService: MasterService) {}
  @Get('/get-all-role')
  async updateAccessTokenService(@Req() request, @Res() response) {
    const res = await this.masterService.getAllUserRole();
    return response.status(200).json(res);
  }
}
