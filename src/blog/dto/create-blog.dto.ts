import { IsEnum, IsNotEmpty, IsOptional, IsString, MaxLength, MinLength } from "class-validator"
import { postStatus } from "../schema/blog.schema"
import { Reaction } from "src/reaction/schema/reaction.schema"
import { Comment } from "src/comment/schema/comment.schema"
import { Category } from "src/category/schema/category.schema"
import { Transform, TransformFnParams } from "class-transformer"
import { ApiProperty } from "@nestjs/swagger"

export class CreateBlogDto {
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
    @ApiProperty()
    @IsNotEmpty({message: "Post status is missing"})
    @IsEnum(postStatus)
    status: postStatus
    @ApiProperty()
    @Transform(({ value }: TransformFnParams) => value.trim())
    @IsNotEmpty({ message: 'Category cannot be empty' })
    @IsString({ message: 'Category must be a string' })
    category: Category
    @ApiProperty()
    @IsOptional()
    reaction: Reaction
    @ApiProperty()
    @IsOptional()
    comment: Comment
}

