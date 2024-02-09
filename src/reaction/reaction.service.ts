import { Injectable } from '@nestjs/common';
import { CreateReactionDto } from './dto/create-reaction.dto';
import { InjectModel } from '@nestjs/mongoose';
import { Reaction } from './schema/reaction.schema';
import { Model } from 'mongoose';
import { ObjectId } from 'mongodb';
import { Blog } from 'src/blog/schema/blog.schema';

@Injectable()
export class ReactionService {
  constructor(
    @InjectModel(Reaction.name) private reactionSchema: Model<Reaction>,
    @InjectModel(Blog.name) private blogSchema: Model<Blog>,
  ) {}
  async reactionController(createReactionDto: CreateReactionDto, req: any) {
    try {
      if (req?.user?.role === 'admin') {
        return {
          message:
            'As an admin you can not react to blogs. We are working on it',
        };
      }
      const { blog, reaction } = createReactionDto;
      const blogExists = await this.blogSchema.findById(blog);
      if(!blogExists){
        return {message: "Invalid blog id sent!"}
      }
      const bId = new ObjectId(blog);
      const reactionExists = await this.reactionSchema.find({
        blog: bId,
        user: req?.user?._id,
      });
      console.log(reactionExists)
      if (reactionExists.length === 0) {
       const newReact = await this.reactionSchema.create({
          reaction,
          blog: bId,
          user: req?.user?._id,
        });
        const reactionBlog = await this.blogSchema.findById(blog)
        reactionBlog.reaction.push(newReact._id);
        await reactionBlog.save();
        return { message: 'created' };
      }
      if (reactionExists[0].reaction !== reaction) {
        await this.reactionSchema.findByIdAndUpdate(reactionExists[0]._id, {
          reaction,
        });
        return { message: 'changed' };
      }
      const deletedReaction = await this.reactionSchema.findByIdAndDelete(reactionExists[0]._id);
      const reactionBlog = await this.blogSchema.findById(blog);
        const index = reactionBlog.reaction.indexOf(deletedReaction._id);
        reactionBlog.reaction.splice(index, 1)
        await reactionBlog.save();
      return { message: 'deleted' };
    } catch (err) {
      return { error: 'Server throws an error. Please review your request body' };
    }
  }
}
