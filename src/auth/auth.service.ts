/* eslint-disable prettier/prettier */
import {
  BadRequestException,
  ConflictException,

  Injectable,
  NotFoundException,
  NotImplementedException,
} from '@nestjs/common';
import { User } from './schema/user.schema';
import { Model } from 'mongoose';
import { SignUpDto } from './dto/signup.dto';
import { LogInDto } from './dto/login.dto';
import { InjectModel } from '@nestjs/mongoose';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { ObjectId } from 'mongodb';
import { ResetDto } from './dto/reset.dto';
import * as nodemailer from 'nodemailer';
import { CloudinaryService } from 'src/cloudinary/cloudinary.service';
import { PinDto } from './dto/pin.dto';
import { PasswordDto } from './dto/password.dto';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name)
    private userModel: Model<User>,
    private jwtService: JwtService,
    private cloudinary: CloudinaryService,
  ) {}

  // sign up controller
  async signUp(signUpDto: SignUpDto, file: Express.Multer.File) {
    if (!file) {
      return { error: true, message: 'Image is required' };
    }
    const { username, name, email, password, role, userStatus } = signUpDto;
    const userExists = await this.userModel.findOne({ email: email });
    if (userExists)
      throw new ConflictException(
        'User already exists. PLease try different email..',
      );
    const image = await this.cloudinary.uploadImage(file).catch((err) => {
      console.log(err);
      throw new BadRequestException(
        'File uploading failed. Please select valid file type',
      );
    });
    const hashed = await bcrypt.hash(password, 10);
    await this.userModel.create({
      username,
      name,
      email,
      password: hashed,
      role,
      image: image.secure_url,
      userStatus,
    });
    return { success: true, message: "User has been created!" };
  }
  // returns user by email
  async findUserByEmail (email: string){
    const user = await this.userModel.findOne({email});
    return user;
  }
  // checks password
  async matchPassword(password:string, hash:string){
    const passwordMatched = await bcrypt.compare(password, hash);
    if(passwordMatched){
      return true;
    }
    return false;
  }
  // assign token
  async assignToken(id:string){
    return { token: this.jwtService.sign({ id }) };
  }
  // login controller
  async logIn(logInDto: LogInDto) {
    try {
      const { email, password } = logInDto;
      console.log(email, password)
      const user = await this.userModel.findOne({ email: email });
      console.log(user);
     
     
      const passwordMatched = await bcrypt.compare(password, user.password);
      if (!passwordMatched) {
        throw new BadRequestException();
      }
      return { token: this.jwtService.sign({ id: user._id }) };
    } catch (err) {
      return { error: 'Server error occurred!!!!!!' };
    }
  }
  // block or unblock user
  async userStatus(id: string, req: any) {
    const loggedUser = req?.user;
    if (loggedUser.role === 'admin') {
      const userId = new ObjectId(id);
      const userExists = await this.userModel.findById(userId);
      if (!userExists) {
        return { message: 'invalid id passed, User does not exist' };
      }
      await this.userModel.findByIdAndUpdate(userExists._id, {
        userStatus: userExists.userStatus === 'unblock' ? 'block' : 'unblock',
      });
      return {
        message: `user has been ${userExists.userStatus === 'block' ? 'unblocked ' : 'blocked '}by ${loggedUser.name}`,
      };
    }
    return {
      message: 'Only admin has right to block | unblock user.',
    };
  }
  // sends user with pincode
  async resetPassword(resetDto: ResetDto) {
    try {
      const { email } = resetDto;
      console.log(email);
      const user = await this.userModel.findOne({ email: email });
      if (!user) {
        throw new NotFoundException('User with this email does not exist');
      }
      const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: '-----',
          pass: '--------',
        },
      });
      const pinCode = Math.floor(1000 + Math.random() * 9000).toString();
      console.log(pinCode);
      const mailOptions = {
        from: '--------',
        to: email,
        subject: 'Subject',
        text: 'your pin code is ' + pinCode,
      };
      await transporter.sendMail(mailOptions);
      const token = this.jwtService.sign({
        user: user._id,
        pin: pinCode,
      });
      return { token };
    } catch (err) {
      throw new NotImplementedException(
        'It seems server can not send email on this mail. Please try valid and verified email.',
      );
    }
  }
  // validate pin code
  async validatePinCode(pinDto: PinDto, req: any) {
    const { pin } = pinDto;
    const { pinCode } = req;
    if (pinCode || pin) {
      throw new BadRequestException();
    }
    if (pinCode !== pin) {
      throw new BadRequestException({}, 'Wrong pin code entered!');
    }
    return {
      error: false,
      message: 'You are being redirected to new password page!',
    };
  }
  // change password
  async changePassword(passwordDto: PasswordDto, req: any) {
    const {password} = passwordDto; 
     const user = await this.userModel.findOne({_id: req?.user?._id});
     if(!user){
      throw new NotFoundException("You are not member of this blog app. Please sign up first")
     }
     const hash = await bcrypt.hash(password, 10);
     if(!hash){
      throw new BadRequestException("Invalid password.");
     }
     user.password = hash;
     await user.save();
     return {message: "Password changed"}
  }
}
