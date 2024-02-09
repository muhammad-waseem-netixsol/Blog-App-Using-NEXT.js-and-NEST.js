import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { MongooseModule } from '@nestjs/mongoose';
import { BlogModule } from './blog/blog.module';
import { ReactionModule } from './reaction/reaction.module';
import { CategoryModule } from './category/category.module';
import { CommentModule } from './comment/comment.module';
import { CloudinaryModule } from './cloudinary/cloudinary.module';

@Module({
  imports: [AuthModule, MongooseModule.forRoot("mongodb+srv://infowaseem1234:nestjs@cluster0.xkb1xah.mongodb.net/nestjsblog"), BlogModule, CommentModule, ReactionModule, CategoryModule, CloudinaryModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
