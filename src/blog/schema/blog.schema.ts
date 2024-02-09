import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import mongoose, { Document } from "mongoose";
import { User } from "src/auth/schema/user.schema";
import { Category } from "src/category/schema/category.schema";
import { Comment } from "src/comment/schema/comment.schema";
import { Reaction } from "src/reaction/schema/reaction.schema";
export enum postStatus {
    PENDING= "pending",
    APPROVED="approved",
    REJECTED="rejected"
}
@Schema({timestamps: true})
export class Blog extends Document{
    @Prop()
    heading: string

    @Prop()
    text: string 

    @Prop()
    image: string

    @Prop({default: "pending"})
    status: postStatus

    @Prop({type: mongoose.Types.ObjectId, ref: "User"})
    user: User

    @Prop({type: mongoose.Types.ObjectId, ref: "Category"})
    category: Category

    @Prop([{type :mongoose.Types.ObjectId, ref: "Reaction", default:[]}])
    reaction: Reaction[]

    @Prop([{type :mongoose.Types.ObjectId, ref: "Comment", default:[]}])
    comment: Comment[]

}

export const blogSchema = SchemaFactory.createForClass(Blog);

