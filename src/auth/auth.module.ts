// Import necessary modules and services
import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { userSchema } from './schema/user.schema';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { JwtStrategy } from './jwt.strategy';
import { CloudinaryService } from 'src/cloudinary/cloudinary.service';

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.register({
      secret: 'secret',
      signOptions: { expiresIn: '3d' },
    }),
    MongooseModule.forFeature([{ name: 'User', schema: userSchema }]),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy, CloudinaryService],
  exports: [JwtStrategy, PassportModule]
})
export class AuthModule {}
