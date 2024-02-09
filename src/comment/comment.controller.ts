import { Controller, Post, Body, Req, Delete, UseGuards, Param, Put } from '@nestjs/common';
import { CommentService } from './commment.service';
import { CreateCommentDto } from './dto/create-comment.dto';
import { AuthGuard } from '@nestjs/passport';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';

@Controller('comment')
@ApiTags("Comments")
export class CommentController {
  constructor(private readonly commentService: CommentService,) {}

  @Post()
  @ApiOperation({summary:"CREATES COMMENT"})
  @ApiResponse({status: 200, description: "SUCCESSFULL"})
  @ApiResponse({status: 404, description: "BAD REQUEST"})
  @UseGuards(AuthGuard())
  create(@Body() createCommentDto: CreateCommentDto,  @Req() req:any) {
    return this.commentService.create(createCommentDto, req);
  }

  @Put(':id')
  @ApiOperation({summary:"UPDATES A COMMENT"})
  @ApiResponse({status: 200, description: "SUCCESSFULL"})
  @ApiResponse({status: 404, description: "BAD REQUEST"})
  @UseGuards(AuthGuard())
  updateComment(@Param('id') id: string,@Body() createCommentDto: CreateCommentDto,  @Req() req:any) {
    return this.commentService.update(id,createCommentDto, req);
  }

  @Delete(':id')
  @ApiOperation({summary:"DELETES A COMMENT"})
  @ApiResponse({status: 200, description: "SUCCESSFULL"})
  @ApiResponse({status: 404, description: "BAD REQUEST"})
  @UseGuards(AuthGuard('id'))
  removeComment(@Param() id:string, @Req() req:any) {
    return this.commentService.remove(id, req);
  }  
}
