import { ApiProperty } from "@nestjs/swagger"
import { IsNotEmpty, IsString, MaxLength, MinLength } from "class-validator"



export class UpdateBlogDto {
    @ApiProperty()
    @IsNotEmpty({message:"Heading can not be empty"})
    @IsString({message: "Heading must be valid string"})
    heading: string
    @ApiProperty()
    @IsNotEmpty({message:"Text body can not be empty"})
    @IsString({message: "Heading must be valid string"})
    @MaxLength(1000)
    @MinLength(10)
    text: string 

}
