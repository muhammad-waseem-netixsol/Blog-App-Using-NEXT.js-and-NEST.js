import { Module } from '@nestjs/common';
import { ReactionService } from './reaction.service';
import { ReactionController } from './reaction.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { reactionSchema } from './schema/reaction.schema';
import { AuthModule } from 'src/auth/auth.module';
import { blogSchema } from 'src/blog/schema/blog.schema';

@Module({
  imports: [
    AuthModule,
     MongooseModule.forFeature([{name: "Reaction", schema: reactionSchema}]), MongooseModule.forFeature([{name: "Blog", schema: blogSchema}])],
  controllers: [ReactionController],
  providers: [ReactionService],
})
export class ReactionModule {}
