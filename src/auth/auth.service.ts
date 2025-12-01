import { 
  Injectable, 
  UnauthorizedException, 
  ConflictException, 
  OnModuleInit,
  Inject, 
  forwardRef, 
  NotFoundException 
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { Role } from './enums/roles.enum';
import { User, UserDocument } from './schemas/user.schema';
import { ClienteProfileService } from '../cliente-profile/cliente-profile.service';
import { UploadService } from '../upload/upload.service';

@Injectable()
export class AuthService implements OnModuleInit {
  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    private jwtService: JwtService,
    private clienteProfileService: ClienteProfileService,

    @Inject(forwardRef(() => UploadService))
    private readonly uploadService: UploadService,
  ) {}

  async onModuleInit() {
    await this.createDefaultAdmin();
  }

  private async createDefaultAdmin() {
    const existingAdmin = await this.userModel.findOne({ email: 'admin@sistema.com' });

    if (!existingAdmin) {
      const hashedPassword = await bcrypt.hash('Admin123456', 10);
      await this.userModel.create({
        email: 'admin@sistema.com',
        password: hashedPassword,
        role: Role.ADMIN,
      });
      console.log('✅ Usuario ADMIN creado: admin@sistema.com / Admin123456');
    }
  }

  /**
   * Registro público - Crea User + Profile correspondiente según el rol
   * Factory Pattern: Crea el tipo de profile según el rol
   */
  async register(registerDto: RegisterDto) {
    const existingUser = await this.userModel.findOne({ email: registerDto.email });
    if (existingUser) {
      throw new ConflictException('El email ya está registrado');
    }

    const hashedPassword = await bcrypt.hash(registerDto.password, 10);

    // 1. Crear User (solo autenticación)
    const newUser = await this.userModel.create({
      email: registerDto.email,
      password: hashedPassword,
      role: registerDto.role,
    });

    try {
      // 2. Crear Profile según el rol (Factory Pattern)
      const userId = (newUser._id as any).toString();

      switch (registerDto.role) {
      case Role.CLIENTE:
        await this.clienteProfileService.create(userId, {
          nombre: registerDto.nombre,
          telefono: registerDto.telefono,
          direccion: registerDto.direccion,
          preferencias: registerDto.preferencias,
        });
        break;
      }

      const userObject = newUser.toObject();
      const { password, ...userWithoutPassword } = userObject;

      return {
        user: userWithoutPassword,
        access_token: this.generateToken(userObject),
      };
    } catch (error) {
      // Si falla la creación del profile, eliminar el user creado (rollback)
      await this.userModel.findByIdAndDelete((newUser._id as any).toString());
      throw error;
    }
  }

  async login(loginDto: LoginDto) {
    const user = await this.userModel.findOne({ email: loginDto.email }).select('+password');

    if (!user) {
      throw new UnauthorizedException('Credenciales inválidas');
    }

    const isPasswordValid = await bcrypt.compare(loginDto.password, user.password);

    if (!isPasswordValid) {
      throw new UnauthorizedException('Credenciales inválidas');
    }

    const userObject = user.toObject();
    const { password, ...userWithoutPassword } = userObject;

    return {
      user: userWithoutPassword,
      access_token: this.generateToken(userObject),
    };
  }

  async getProfile(userId: string) {
    const user = await this.userModel.findById(userId);
    if (!user) {
      throw new UnauthorizedException('Usuario no encontrado');
    }
    const userObject = user.toObject();
    const { password, ...userWithoutPassword } = userObject;
    return userWithoutPassword;
  }

  private generateToken(user: any): string {
    const payload = {
      sub: user._id.toString(),
      email: user.email,
      role: user.role,
    };
    return this.jwtService.sign(payload);
  }

  async getAllUsers() {
    const users = await this.userModel.find().select('-password');
    return users;
  }

  /**
   * Sube una imagen, la asocia al usuario y devuelve el usuario actualizado.
   * @param userId - El ID del usuario que está actualizando su avatar.
   * @param file - El archivo de imagen subido.
   * @returns El objeto User actualizado sin la contraseña.
   */
  async updateAvatar(userId: string, file: Express.Multer.File): Promise<User> {
    // Primero, sube la imagen usando el servicio de upload
    const uploadResult = await this.uploadService.uploadImage(file);

    // Luego, actualiza el documento del usuario en la base de datos con la nueva URL del avatar
    const updatedUser = await this.userModel.findByIdAndUpdate(
      userId,
      { $set: { avatar: uploadResult.url } }, // Actualiza el campo 'avatar'
      { new: true }, // Esta opción hace que devuelva el documento ya actualizado
    ).select('-password'); // Crucial: Nunca devolver la contraseña

    if (!updatedUser) {
      throw new NotFoundException('Usuario no encontrado al intentar actualizar el avatar.');
    }

    return updatedUser;
  }
}
