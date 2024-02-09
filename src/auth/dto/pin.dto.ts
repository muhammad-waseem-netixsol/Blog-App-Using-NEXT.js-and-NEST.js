import { ApiProperty } from "@nestjs/swagger";
import { IsNotEmpty, IsString, Matches, MaxLength, MinLength } from "class-validator";

export class PinDto {

    @ApiProperty()
    @IsNotEmpty({message: "Pin code can not be empty!"})
    @IsString({message: "Pin code is not a string!"})
    @MinLength(4)
    @MaxLength(4)
    @Matches(/^\d{4}$/, { message: 'PIN code must be a 4-digit number' })
    pin: string;
}
