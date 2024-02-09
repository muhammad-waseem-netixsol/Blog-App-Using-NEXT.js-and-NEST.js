import { IsEnum, IsNotEmpty } from "class-validator";
import { ReactionType } from "../schema/reaction.schema";
import { ApiProperty } from "@nestjs/swagger";

export class CreateReactionDto {
    @ApiProperty()
    @IsNotEmpty()
    @IsEnum(ReactionType) 
    reaction: ReactionType
    @ApiProperty()
    @IsNotEmpty()
    blog: string
}
