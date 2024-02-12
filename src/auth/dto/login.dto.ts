import { ApiProperty } from "@nestjs/swagger";
import { IsEmail, IsNotEmpty, IsString, Matches, MaxLength, MinLength } from "class-validator";

export class LogInDto {
    
    @ApiProperty()
    @IsNotEmpty({message:"Email must not be empty!"})
    @IsEmail({}, {message: "Email is not valid!"})
    email: string;

    @ApiProperty()
    @IsNotEmpty({message: "Password can not be empty!"})
    @IsString({message: "Password is not a string!"})
    @Matches(/^(?=.*[a-zA-Z])(?=.*\d)[A-Za-z\d@$!%*?&]*$/, { message: 'Password must be a mixture of letters and numbers, and symbols(optional)' })
    @MinLength(6)
    @MaxLength(20)
    password: string;
}
