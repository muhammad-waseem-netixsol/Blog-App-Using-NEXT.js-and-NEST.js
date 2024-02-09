import { ApiProperty } from "@nestjs/swagger";
import { IsNotEmpty, IsString, Matches, MaxLength, MinLength } from "class-validator";

export class PasswordDto {
    @ApiProperty()
    @IsNotEmpty({message: "Password can not be empty!"})
    @IsString({message: "Password is not a string!"})
    @Matches(/^(?=.*[a-zA-Z])(?=.*\d)[A-Za-z\d@$!%*?&]*$/, { message: 'Password must be a mixture of letters and numbers, and symbols(optional)' })
    @MinLength(6)
    @MaxLength(20)
    password: string;
}
