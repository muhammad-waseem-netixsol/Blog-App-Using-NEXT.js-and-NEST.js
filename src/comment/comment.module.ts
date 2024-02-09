import { Module } from '@nestjs/common';
import { CommentService } from './commment.service';
import { CommentController } from './comment.controller';
import { AuthModule } from 'src/auth/auth.module';
import { MongooseModule } from '@nestjs/mongoose';
import { commentSchema } from './schema/comment.schema';
import { CreateCommentDto } from './dto/create-comment.dto';
import {  blogSchema } from 'src/blog/schema/blog.schema';
import { BlogModule } from 'src/blog/blog.module';

@Module({
  imports:[AuthModule,BlogModule ,MongooseModule.forFeature([{name: "Comment", schema: commentSchema}]),MongooseModule.forFeature([{name: "Blog", schema: blogSchema}])] ,
  controllers: [CommentController],
  providers: [CreateCommentDto,CommentService],
  exports: [CommentModule],
})
export class CommentModule {}
