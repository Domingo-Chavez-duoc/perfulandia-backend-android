import { 
  Controller,
  Post,
  Get,
  Body,
  HttpCode,
  HttpStatus,
  UseGuards,
  UseInterceptors,
  UploadedFile,
  Req,
  BadRequestException,
  ParseFilePipe,
  FileTypeValidator
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth, ApiBody, ApiConsumes } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { CreateProductorUserDto } from './dto/create-productor-user.dto';
import { Public } from './decorators/public.decorator';
import { CurrentUser } from './decorators/current-user.decorator';
import { Roles } from './decorators/roles.decorator';
import { Role } from './enums/roles.enum';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RolesGuard } from './guards/roles.guard';
import { FileInterceptor } from '@nestjs/platform-express';

@ApiTags('Autenticación')
@Controller('auth')
@UseGuards(JwtAuthGuard, RolesGuard)
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Registrar nuevo CLIENTE'})
  @ApiBody({ type: RegisterDto })
  @ApiResponse({ status: 201, description: 'Endpoint público para auto-registro de clientes. Solo se pueden registrar como CLIENTE.'})
  @ApiResponse({ status: 409, description: 'El email ya está registrado' })
  async register(@Body() registerDto: RegisterDto) {
    const result = await this.authService.register(registerDto);
    return {
      success: true,
      message: 'Usuario registrado exitosamente',
      data: result,
    };
  }

  @Public()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Iniciar sesión' })
  @ApiBody({ type: LoginDto })
  @ApiResponse({ status: 200, description: 'Inicio de sesión exitoso' })
  @ApiResponse({ status: 401, description: 'Credenciales inválidas' })
  async login(@Body() loginDto: LoginDto) {
    const result = await this.authService.login(loginDto);
    return {
      success: true,
      message: 'Inicio de sesión exitoso',
      data: result,
    };
  }

  @Get('profile')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Obtener perfil del usuario actual' })
  @ApiResponse({ status: 200, description: 'Perfil obtenido exitosamente' })
  @ApiResponse({ status: 401, description: 'No autorizado' })
  async getProfile(@CurrentUser() user: any) {
    const profile = await this.authService.getProfile(user.userId);
    return {
      success: true,
      data: profile,
    };
  }

  @Get('users')
  @Roles(Role.ADMIN)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Listar todos los usuarios (solo ADMIN)' })
  @ApiResponse({ status: 200, description: 'Lista de usuarios' })
  @ApiResponse({ status: 403, description: 'Acceso denegado - Solo administradores' })
  async getAllUsers() {
    const users = await this.authService.getAllUsers();
    return {
      success: true,
      data: users,
    };
  }

  @Post('avatar')
  @UseGuards(JwtAuthGuard) 
  @UseInterceptors(FileInterceptor('file')) 
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Subir o actualizar mi avatar' })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    schema: {
      type: 'object',
      properties: { file: { type: 'string', format: 'binary' } },
    },
  })
  async uploadMyAvatar(
    @CurrentUser() user: any, // Obtenemos el usuario del token
    @UploadedFile(
      // Validador para asegurar que es una imagen
      new ParseFilePipe({
        validators: [new FileTypeValidator({ fileType: 'image' })],
      }),
    ) file: Express.Multer.File, // Inyectamos el archivo subido
  ) {
    if (!file) {
      throw new BadRequestException('No se proporcionó ningún archivo de imagen.');
    }
    // El controlador solo pasa el trabajo al servicio
    const updatedUser = await this.authService.updateAvatar(user.userId, file);
    return {
      success: true,
      message: 'Avatar actualizado exitosamente',
      data: updatedUser,
    };
  }
}

