import { Module } from '@nestjs/common';
import { CategoryService } from './category.service';
import { CategoryController } from './category.controller';
import { AuthModule } from 'src/auth/auth.module';
import { MongooseModule } from '@nestjs/mongoose';
import { categorySchema } from './schema/category.schema';

@Module({
  imports:[AuthModule, MongooseModule.forFeature([{name: "Category", schema: categorySchema}])],
  controllers: [CategoryController],
  providers: [CategoryService],
})
export class CategoryModule {}
