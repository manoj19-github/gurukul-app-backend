import { IsDefined, IsNotEmpty, IsString } from '@nestjs/class-validator';
import { IsOptional } from 'class-validator';
import { IsValidProperty } from 'src/lib/utils';

export class SignupDTO {
  @IsString()
  @IsNotEmpty()
  user_name: string;
  @IsString()
  role_id: string;
  @IsString()
  @IsNotEmpty()
  password: string;
  @IsString()
  @IsNotEmpty()
  @IsDefined()
  @IsValidProperty(/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/)
  email_id: string;
  @IsString()
  @IsOptional()
  @IsValidProperty(/^[6789]\d{7,9}$/)
  phone_number: string;
}

export class LoginDTO {
  @IsString()
  role_id: string;
  @IsString()
  @IsNotEmpty()
  password: string;
  @IsString()
  @IsNotEmpty()
  @IsDefined()
  @IsValidProperty(/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/)
  email_id: string;
}
export class LoginDTOForGoogle {
  @IsString()
  @IsNotEmpty()
  soToken: string;
  @IsString()
  @IsNotEmpty()
  @IsDefined()
  @IsValidProperty(/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/)
  email_id: string;
}


export class ResetPasswordDTO {
  @IsString()
  @IsNotEmpty()
  @IsDefined()
  @IsValidProperty(/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/)
  email_id: string;
  @IsString()
  @IsNotEmpty()
  code: string;
  @IsString()
  @IsNotEmpty()
  password: string;
  @IsString()
  @IsNotEmpty()
  role_id: string;
}
