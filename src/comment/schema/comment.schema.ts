import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import mongoose, { Document } from "mongoose";
import { User } from "src/auth/schema/user.schema";
import { Blog } from "src/blog/schema/blog.schema";
@Schema({timestamps: true})

export class Comment extends Document{
    @Prop({type: mongoose.Types.ObjectId, ref: "User"})
    user: User
    
    @Prop({type: mongoose.Types.ObjectId, ref: "Blog"})
    blog: Blog

    @Prop()
    comment: string
}

export const commentSchema = SchemaFactory.createForClass(Comment);
