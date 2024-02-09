import { ApiProperty } from "@nestjs/swagger";
import { IsNotEmpty, IsOptional, IsString, MaxLength, MinLength } from "class-validator";
import { User } from "src/auth/schema/user.schema";

export class CreateCommentDto {
    @ApiProperty()
    @IsString({message: "Comment must be a string.."})
    @IsNotEmpty({message: "comment is required"})
    @MinLength(1)
    @MaxLength(100)
    comment:string 
    @ApiProperty()
    @IsOptional()
    user: User
    @ApiProperty()
    @IsNotEmpty()
    blog: string
}
