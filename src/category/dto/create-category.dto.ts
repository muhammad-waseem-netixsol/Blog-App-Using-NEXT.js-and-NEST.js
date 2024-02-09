import { ApiProperty } from "@nestjs/swagger";
import { IsNotEmpty, Matches, MaxLength, MinLength } from "class-validator";

export class CreateCategoryDto {
    @ApiProperty()
    @IsNotEmpty({message:"Category is required!"})
    @MinLength(2)
    @MaxLength(20)
    @Matches(/^[^\s]+$/, { message: "Category text should not contain spaces!" })
    text:string
}
