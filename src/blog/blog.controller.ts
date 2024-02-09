import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Req, UseInterceptors, UploadedFile } from '@nestjs/common';
import { BlogService } from './blog.service';
import { CreateBlogDto } from './dto/create-blog.dto';
import { UpdateBlogDto } from './dto/update-blog.dto';
import { AuthGuard } from '@nestjs/passport';
import { FileInterceptor } from '@nestjs/platform-express';
import { ApiBody, ApiConsumes, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';

@Controller('blog')
@ApiTags("BLOG")
export class BlogController {
  constructor(private readonly blogService: BlogService) {}

  @Post("/create-blog")
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        heading: { type: 'string' },
        text: { type: 'string' },
        reaction: { type: 'string' },
        comment: { type: 'string' },
        status: { type: 'string' },
        category: { type: "string" },
        file: {
          type: 'string',
          format: 'binary',
        },
      },
    },
  })
  @ApiOperation({summary:"CREATE BLOG"})
  @ApiResponse({status: 200, description: "SUCCESSFULL"})
  @ApiResponse({status: 404, description: "BAD REQUEST"})
  @UseGuards(AuthGuard())
  @UseInterceptors(FileInterceptor("file"))
  create(@Body() createBlogDto: CreateBlogDto, @Req() req:any, @UploadedFile() file: Express.Multer.File) {
    return this.blogService.create(createBlogDto, req.user, file);
  }

  @Get("/get-blogs")
  @ApiOperation({summary:"GET ALL BLOG"})
  @ApiResponse({status: 200, description: "SUCCESSFULL"})
  @ApiResponse({status: 404, description: "BAD REQUEST"})
  findAllBlogs() {
    return this.blogService.findAll();
  }

  @Get(':id')
  @ApiOperation({summary:"GET BLOG BY ID"})
  @ApiResponse({status: 200, description: "SUCCESSFULL"})
  @ApiResponse({status: 404, description: "BAD REQUEST"})
  @UseGuards(AuthGuard())
  findOneBlog(@Param('id') id: string) {
    return this.blogService.findOne(id);
  }

  @Patch('/update/:id')
  @ApiOperation({summary:"UPDATE BLOG"})
  @ApiResponse({status: 200, description: "SUCCESSFULL"})
  @ApiResponse({status: 404, description: "BAD REQUEST"})
  @UseGuards(AuthGuard())
  update(@Param('id') id: string, @Body() updateBlogDto: UpdateBlogDto, @Req() req:any) {
    return this.blogService.update(id, updateBlogDto, req);
  }

  @Delete('/delete/:id')
  @ApiOperation({summary:"DELETE BLOG BY ID"})
  @ApiResponse({status: 200, description: "SUCCESSFULL"})
  @ApiResponse({status: 404, description: "BAD REQUEST"})
  @UseGuards(AuthGuard())
  removeBlog(@Param('id') id: string, @Req() req:any) {
    return this.blogService.remove(id, req);
  }

  @Patch('/approve/:id')
  @ApiOperation({summary:"ADMIN APPROVES BLOG"})
  @ApiResponse({status: 200, description: "SUCCESSFULL"})
  @ApiResponse({status: 404, description: "BAD REQUEST"})
  @UseGuards(AuthGuard())
  approveBlog(@Param('id') id: string, @Req() req:any) {
    return this.blogService.approve(id, req);
  }
  @Patch('/reject/:id')
  @ApiOperation({summary:"ADMIN REJECTS BLOG"})
  @ApiResponse({status: 200, description: "SUCCESSFULL"})
  @ApiResponse({status: 404, description: "BAD REQUEST"})
  @UseGuards(AuthGuard())
  rejectBlog(@Param('id') id: string, @Req() req:any) {
    return this.blogService.reject(id, req);
  }
}
