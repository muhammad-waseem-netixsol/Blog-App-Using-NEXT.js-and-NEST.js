import {
  IsString,
  IsEmail,
  IsNotEmpty,
  Matches,
  IsAlpha,
  IsEnum,
  MinLength,
  MaxLength,
  IsOptional,
} from 'class-validator';
import { role, userStatus } from '../schema/user.schema';
import { ApiProperty } from '@nestjs/swagger';


export class SignUpDto {
  @ApiProperty()
  @IsNotEmpty({ message: 'Username is empty!' })
  @IsString({ message: 'Username must be mixture of letters and numbers!' })
  @Matches(/^[a-zA-Z0-9]*$/, {
    message: 'Username must contain only letters and numbers',
  })
  @MinLength(6)
  @MaxLength(10)
  username: string;

  @ApiProperty()
  @IsNotEmpty({ message: 'Name is empty!' })
  @IsString({ message: 'Name must be a valid charaters string!' })
  @IsAlpha()
  @MinLength(6)
  @MaxLength(20)
  name: string;

  @ApiProperty()
  @IsNotEmpty({ message: 'Email must not be empty!' })
  @IsEmail({}, { message: 'Email is not valid!' })
  email: string;

  @ApiProperty()
  @IsNotEmpty({ message: 'Password can not be empty!' })
  @IsString({ message: 'Password is not a string!' })
  @Matches(/^(?=.*[a-zA-Z])(?=.*\d)[A-Za-z\d@$!%*?&]*$/, {
    message:
      'Password must be a mixture of letters and numbers, and symbols(optional)',
  })
  @MinLength(6)
  @MaxLength(20)
  password: string;

  @ApiProperty()
  @IsNotEmpty({ message: 'Role is not selected!' })
  @IsEnum(role)
  role: role;
  
  @ApiProperty()
  @IsOptional()
  @IsEnum(userStatus)
  userStatus: userStatus;

}
