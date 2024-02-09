import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import { Document } from "mongoose";

@Schema({timestamps:true})
export class Category extends Document {
    @Prop()
    text: string
}

export const categorySchema = SchemaFactory.createForClass(Category)