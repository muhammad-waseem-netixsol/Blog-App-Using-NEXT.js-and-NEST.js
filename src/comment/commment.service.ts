import { Injectable } from '@nestjs/common';
import { CreateCommentDto } from './dto/create-comment.dto';
// import { UpdateCommentDto } from './dto/update-comment.dto';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Comment } from './schema/comment.schema';
import { Blog } from 'src/blog/schema/blog.schema';
import { ObjectId } from 'mongodb';

@Injectable()
export class CommentService {
  constructor(
    @InjectModel(Comment.name) private commentSchema: Model<Comment>,
    @InjectModel(Blog.name) private blogSchema: Model<Blog>,
  ) {}
  async create(createCommentDto: CreateCommentDto, req: any) {
    try {
      if (req?.user?.role !== 'admin') {
        const { comment, blog } = createCommentDto;
        const blogExists = await this.blogSchema.findOne({ _id: blog });
        if (!blogExists) {
          return { message: 'Blog with this id does not exists!' };
        }
        const commentIns = new this.commentSchema();
        commentIns.user = req.user._id;
        commentIns.blog = blogExists._id;
        commentIns.comment = comment;
        const commentDoc = await commentIns.save();
        const blogDoc = await this.blogSchema.findById(commentDoc.blog);
        blogDoc.comment.push(commentDoc._id);
        await blogDoc.save();
        return {message: "comment created!"}

      }
      return { message: 'Admin can not comment on blog.' };
    } catch (err) {
      return {
        error: 'Server throws an error Please review your request body!',
      };
    }
  }

  async remove(id: string, req: any) {
    try {
      if(req?.user?.role === "admin"){
        return {message: "Admin can not delete any comment"}
      }
      const commentId = new ObjectId(id);
      const commentExists = await this.commentSchema.findOne({
        user: req.user._id,
        _id: commentId,
      });
      if (!commentExists) {
        return { message: 'Comment does not exist or it was not created by you' };
      }
      await this.commentSchema.deleteOne({
        user: req.user._id,
        _id: commentId,
      });
      return { type: 'success', operation: 'Comment deleted!' };
    } catch (err) {
      return {
        error: 'Server throws an error Please review your request body!',
      };
    }
  }

  async update(id: string, createCommentDto: CreateCommentDto, req: any) {
    try {
      if(req?.user?.role !== "admin"){
        const { blog, comment } = createCommentDto;
        const cId = new ObjectId(id);
        const userId = req?.user?._id;
        const blogId = new ObjectId(blog);
        const commentExists = await this.commentSchema.findOne({
          _id: cId,
          user: userId,
          blog: blogId,
        });
        if (!commentExists) {
          return { message: 'Comment not found!' };
        }
        await this.commentSchema.findByIdAndUpdate(id, { comment });
        return { message: 'Comment updated!' };
      }
      return {message : "Admin can not update the comment!"}
    } catch (err) {
      return {
        error: 'Server throws an error Please review your request body!',
      };
    }
  }
}
