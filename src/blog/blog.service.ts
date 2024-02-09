import { BadRequestException, Injectable } from '@nestjs/common';
import { CreateBlogDto } from './dto/create-blog.dto';
import { UpdateBlogDto } from './dto/update-blog.dto';
import { InjectModel } from '@nestjs/mongoose';
import { Blog, postStatus } from './schema/blog.schema';
import { Model } from 'mongoose';
import { User } from 'src/auth/schema/user.schema';
import { CloudinaryService } from 'src/cloudinary/cloudinary.service';

@Injectable()
export class BlogService {
  constructor(@InjectModel(Blog.name) private blogSchema: Model<Blog>, private cloudinary:CloudinaryService) {}
  // creates a new blog
  async create(createBlogDto: CreateBlogDto, user: User, file:Express.Multer.File) {
    try{
      if(user.role === "writer"){
        const uploadedfile = await this.cloudinary.uploadImage(file).catch((err)=> {
          throw new BadRequestException(err)
        })
      const { heading, status, text, category } = createBlogDto;
      const blog = new this.blogSchema();
      blog.heading = heading;
      blog.status = status;
      blog.text = text;
      blog.user = user._id;
      blog.image = uploadedfile.secure_url;
      blog.category = category;
      const newBlog = await blog.save();
      return newBlog;
      }
      return {message: "Only user with writer account can create blog!"}
    }catch(err){
      return {error: "Server error"}
    }
    

  }
  // it simply returns all blog
  async findAll() {
    return await this.blogSchema.find();
  }
  // returns a blog using id
  async findOne(id: string) {
    return await this.blogSchema.findById(id);
  }
  // updates a blog
  async update(id: string, updateBlogDto: UpdateBlogDto, req: any) {
    try{
      if(req.user.role === "writer"){
        const blogExists = await this.blogSchema.findOne({_id:id, user: req.user._id});
      if (!blogExists) {
        return { error: 'Invalid blog id has been sent or this was not created by you!' };
      }
      const { text, heading } = updateBlogDto;
      await this.blogSchema.findByIdAndUpdate(id, {
        text,
        heading,
      });
      return { message: 'Blog has been updated!' };
      }
      return {message: "Only user with writer account can update own blog!"}
    }catch(err){
      return {error: "Invalid data passed in the request body."}
    }
    
  }
  // deletes a blog 
  async remove(id: string, req:any) {
    try{
      if(req.user.userStatus === "user"){
       return {message: "User account can not delete any blog."} 
      }
      const blogExists = await this.blogSchema.findById(id);
      if(!blogExists){
        return {message: "Blog You trying to remove does not exist"}
      }
      await this.blogSchema.findOneAndDelete({_id:id, user:req.user._id});
      return { message: `blog with with ${id} has been deleted!` };
    }catch(err){
      return {error: "Ooppss! invalid data in the req body"}
    }
    
  }

  // approves a blog 
  async approve(id: string, req:any) {
    try{
      const user = req?.user;
      if(user.role !== "admin"){
        return {message: "Only admin "}
      }
      const blogExists = await this.blogSchema.findById(id);
      if(!blogExists){
        return {error: "Blog not found"};
      }
      blogExists.status = postStatus.APPROVED;
      await blogExists.save();
      return {message: "Post has been approved"};
    }catch(err){
      return {error: "Ooppss! invalid data in the req body"}
    }
  }
  
  // rejects a blog 
  async reject(id: string, req:any) {
    try{
      const user = req?.user;
      if(user.role !== "admin"){
        return {message: "Only admin can approved and reject posts"}
      }
      const blogExists = await this.blogSchema.findById(id);
      if(!blogExists){
        return {error: "Blog not found"};
      }
      blogExists.status = postStatus.REJECTED;
      await blogExists.save();
      return {message: "Post has been rejected"};
    }catch(err){
      return {error: "Ooppss! invalid data in the req body"};
    }
  }
}
