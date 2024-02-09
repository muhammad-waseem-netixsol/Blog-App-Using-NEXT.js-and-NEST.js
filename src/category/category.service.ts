import { Injectable } from '@nestjs/common';
import { CreateCategoryDto } from './dto/create-category.dto';
import { InjectModel } from '@nestjs/mongoose';
import { Category } from './schema/category.schema';
import { Model } from 'mongoose';
import { ObjectId } from 'mongodb';

@Injectable()
export class CategoryService {
  constructor(
    @InjectModel(Category.name) private categorySchema: Model<Category>
  ) {}
  async create(createCategoryDto: CreateCategoryDto, req:any) {
    try{
      if(req.user.role === "admin"){
        const { text } = createCategoryDto;
        const categoryExists = await this.categorySchema.findOne({ text });
        if (categoryExists) {
          return { message: 'This category already exists.' };
        }
        await this.categorySchema.create({ text });
        return { message: 'Category added!' };
      }
      return {message: "Only admin can create categories!"} 
    }catch(err){
      return {error: "you have sent bad request to the server. Please review your request body"}
    } 
  }

  async update(id: string, createCategoryDto: CreateCategoryDto, req:any) {
    try{
      if(req?.user?.role === "admin"){
        const { text } = createCategoryDto;
        const cId = new ObjectId(id);
        const categoryExists = await this.categorySchema.findById(cId);
        if (!categoryExists) {
          return { error: 'Category with this id does not exist!' };
        }
        await this.categorySchema.findByIdAndUpdate(cId, { text });
        return { message: 'category updated!' };
      }
    }catch(err){
      return {error: "you have sent bad request to the server. Please review your request body"}
    }
  }

  async remove(id: string, req:any) {
    try{
      if(req?.user?.role !== "admin"){
        return {message: "Only admin can delete the categry!"}
      }
    const ctgryId = new ObjectId(id);
    const category = await this.categorySchema.findById(ctgryId);
    if(!category){
      return {message: "category does not exist!"}
    }
    await this.categorySchema.findByIdAndDelete(ctgryId);
    return {message: "deleted"}
    }catch(err){
      return {error: "you have sent bad request to the server. Please review your request body"}
    }
  } 
}
