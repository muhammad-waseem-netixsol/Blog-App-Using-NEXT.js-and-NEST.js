import { Controller, Post, Body, UseGuards, Req } from '@nestjs/common';
import { ReactionService } from './reaction.service';
import { CreateReactionDto } from './dto/create-reaction.dto';
import { AuthGuard } from '@nestjs/passport';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';

@Controller('reaction')
@ApiTags("Reaction")
export class ReactionController {
  constructor(private readonly reactionService: ReactionService) {}

  @Post()
  @ApiOperation({summary:"Reactions"})
  @ApiResponse({status: 200, description: "SUCCESSFULL"})
  @ApiResponse({status: 404, description: "BAD REQUEST"})
  @UseGuards(AuthGuard())
  handleReaction(@Body() createReactionDto: CreateReactionDto, @Req() req:any) {
    return this.reactionService.reactionController(createReactionDto, req);
  }
}
