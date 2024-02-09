import { Injectable, UnauthorizedException } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { PassportStrategy } from "@nestjs/passport";
import { Model } from "mongoose";
import { ExtractJwt, Strategy } from "passport-jwt";
import { User } from "./schema/user.schema";

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy){
    constructor(
        @InjectModel(User.name)
        private userModel : Model<User>
    ){
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: "secret"
        })
    }

    async validate(payload){
        const {id, pinCode} = payload;
        const user = await this.userModel.findById(id);
        if(!user){
            throw new UnauthorizedException("Login first to access this endpoint.")
        }
        if(pinCode){
            return {user, pinCode};
        }
        return user;
    }
}