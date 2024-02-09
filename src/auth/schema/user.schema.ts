import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import { Document } from "mongoose";

export enum userStatus {
    BLOCK="block",
    UNBLOCK="unblock"
};
export enum role {
    USER="user",
    ADMIN="admin",
    WRITTER="writer"
}
@Schema({
    timestamps: true
})
export class User extends Document{
    @Prop()
    username:string

    @Prop()
    name:string

    @Prop({unique: [true, "Duplicate email! Please enter unique email..."]})
    email:string

    @Prop()
    password:string

    @Prop()
    role:role

    @Prop()
    image:string

    @Prop({default: "unblock"})
    userStatus: userStatus
}

export const userSchema = SchemaFactory.createForClass(User);
