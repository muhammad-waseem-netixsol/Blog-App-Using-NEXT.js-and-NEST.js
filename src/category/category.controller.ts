import {
  Controller,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  UseGuards,
  Req,
} from '@nestjs/common';
import { CategoryService } from './category.service';
import { CreateCategoryDto } from './dto/create-category.dto';
import { AuthGuard } from '@nestjs/passport';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';

@Controller('category')
@ApiTags('Category')
export class CategoryController {
  constructor(private readonly categoryService: CategoryService) {}

  @Post()
  @ApiOperation({summary:"CREATES CATEGORY"})
  @ApiResponse({status: 200, description: "SUCCESSFULL"})
  @ApiResponse({status: 404, description: "BAD REQUEST"})
  @UseGuards(AuthGuard())
  create(@Body() createCategoryDto: CreateCategoryDto, @Req() req:any) {
    return this.categoryService.create(createCategoryDto, req);
  }

  @Patch(':id')
  @ApiOperation({summary:"UPDATES A CATEGORY"})
  @ApiResponse({status: 200, description: "SUCCESSFULL"})
  @ApiResponse({status: 404, description: "BAD REQUEST"})
  @UseGuards(AuthGuard())
  update(
    @Param('id') id: string,
    @Body() createCategoryDto: CreateCategoryDto,
    @Req() req:any
  ) {
    return this.categoryService.update(id, createCategoryDto, req);
  }

  @Delete(':id')
  @ApiOperation({summary:"DELETE A CATEGORY"})
  @ApiResponse({status: 200, description: "SUCCESSFULL"})
  @ApiResponse({status: 404, description: "BAD REQUEST"})
  @UseGuards(AuthGuard())
  remove(@Param('id') id: string, @Req() req:any) {
    return this.categoryService.remove(id, req);
  }
}
