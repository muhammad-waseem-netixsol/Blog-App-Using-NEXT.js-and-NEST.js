import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import mongoose, { Document } from "mongoose";
import { User } from "src/auth/schema/user.schema";
import { Blog } from "src/blog/schema/blog.schema";
export enum ReactionType {
    LIKE="like",
    HEART="heart",
    CLAP="clap"
};
@Schema({timestamps:true})
export class Reaction extends Document{

    @Prop()
    reaction: ReactionType

    @Prop({type: mongoose.Types.ObjectId, ref: "User"})
    user: User

    @Prop({type: mongoose.Types.ObjectId, ref: "Blog"})
    blog: Blog

}

export const reactionSchema = SchemaFactory.createForClass(Reaction);
