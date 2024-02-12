import { Body, Controller,  ForbiddenException,  HttpStatus,  NotFoundException,  Param, Patch, Post, Req, UnauthorizedException, UploadedFile, UseGuards, UseInterceptors } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignUpDto } from './dto/signup.dto';
import { LogInDto } from './dto/login.dto';
import { AuthGuard } from '@nestjs/passport';
import { ResetDto } from './dto/reset.dto';
import { FileInterceptor } from '@nestjs/platform-express';
import { PinDto } from './dto/pin.dto';
import { PasswordDto } from './dto/password.dto';
import { ApiBody, ApiConsumes, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';

@Controller('auth')
@ApiTags("Authentication")
export class AuthController {
  constructor(private readonly authService: AuthService) {}
  @Post("/signup")
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        username: { type: 'string' },
        name: { type: 'string' },
        email: { type: 'string' },
        password: { type: 'string' },
        role: { type: 'string' },
        userStatus: { type: "string" },
        file: {
          type: 'string',
          format: 'binary',
        },
      },
    },
  })
  @ApiOperation({summary:"THIS SIGNS YOU UP"})
  @ApiResponse({status: 200, description: "SUCCESSFULL"})
  @ApiResponse({status: 404, description: "BAD REQUEST"})
  @UseInterceptors(FileInterceptor('file'))
  signUp(@Body() signUpDto:SignUpDto, @UploadedFile() file: Express.Multer.File) {
    return this.authService.signUp(signUpDto, file);
  }
  @Post("/login")
  @ApiOperation({summary:"THIS LOGS YOU IN"})
  @ApiResponse({status: 200, description: "SUCCESSFULL"})
  @ApiResponse({status: 404, description: "BAD REQUEST"})
  async logIn(@Body() logInDto:LogInDto) {
    const { email } = logInDto;
    // using find user service
    const user = await this.authService.findUserByEmail(email);
    if (!user) {
      throw new UnauthorizedException("Invalid Credentials!");
    }
    if (user.userStatus === 'block') {
      throw new ForbiddenException("This user is blocked by admin. Contact admin!")
    }
    const {password} = logInDto;
    const passwordMatched = await this.authService.matchPassword(password, user.password);
    if(!passwordMatched){
      throw new UnauthorizedException("Invalid Credentials!");
    }
    this.authService.assignToken(user._id);
     return this.authService.logIn(logInDto);
  }
  @Patch(":userId")
  @ApiOperation({summary:"USER STATUS"})
  @ApiResponse({status: 200, description: "SUCCESSFULL"})
  @ApiResponse({status: 404, description: "BAD REQUEST"})
  @UseGuards(AuthGuard())
  changeUserStatus(@Param('userId') id: string, @Req() req:any) {
    console.log("id =>", id)
    return this.authService.userStatus(id, req);
  }

  @Post("/reset-password")
  @ApiOperation({summary:"RESET PASS"})
  @ApiResponse({status: 200, description: "SUCCESSFULL"})
  @ApiResponse({status: 404, description: "BAD REQUEST"})
  resetPassword(@Body() resetDto: ResetDto) {
    return this.authService.resetPassword(resetDto);
  }
  @Post("/validate-pin")
  @ApiOperation({summary:"VALIDATE PIN"})
  @ApiResponse({status: 200, description: "SUCCESSFULL"})
  @ApiResponse({status: 404, description: "BAD REQUEST"})
  validatepinCode(@Body() pinDto: PinDto, @Req() req:any) {
    return this.authService.validatePinCode(pinDto, req);
  }
  @Patch("/change-password")
  @ApiOperation({summary:"CHANGE PASS"})
  @ApiResponse({status: 200, description: "SUCCESSFULL"})
  @ApiResponse({status: 404, description: "BAD REQUEST"})
  changePassword(@Body() passwordDto: PasswordDto, @Req() req:any) {
    return this.authService.changePassword(passwordDto, req);
  }

}
