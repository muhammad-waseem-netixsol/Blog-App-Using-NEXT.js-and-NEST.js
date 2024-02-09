import { ApiProperty } from "@nestjs/swagger";
import { IsEmail, IsNotEmpty  } from "class-validator";

export class ResetDto {
    @ApiProperty()
    @IsNotEmpty({message:"Email must not be empty!"})
    @IsEmail({}, {message: "Email is not valid!"})
     email: string;

}
