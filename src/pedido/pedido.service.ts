import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { CreatePedidoDto } from './dto/create-pedido.dto';
import { UpdatePedidoDto } from './dto/update-pedido.dto';
import { Pedido, PedidoDocument } from './schemas/pedido.schema';
import { ClienteProfileService } from '../cliente-profile/cliente-profile.service';
@Injectable()
export class PedidoService {
  constructor(
    @InjectModel(Pedido.name) private pedidoModel: Model<PedidoDocument>,
    private clienteProfileService: ClienteProfileService) {}

  async create(createPedidoDto: CreatePedidoDto, userId: string): Promise<Pedido> {
    let clienteId: string;

    // 1. Determinar el cliente
    if (createPedidoDto.cliente) {
      // Si se especificó un cliente (caso ADMIN), usarlo directamente
      clienteId = createPedidoDto.cliente;
    } else {
      // Si no, buscar el ClienteProfile del usuario autenticado
      const clienteProfile = await this.clienteProfileService.findByUserId(userId);
      clienteId = (clienteProfile as any)._id.toString();
    }

    // 2. Crear el pedido
    const nuevoPedido = await this.pedidoModel.create({
      ...createPedidoDto,
      cliente: new Types.ObjectId(clienteId),
    });

    return nuevoPedido;
  }

  async findAll(): Promise<Pedido[]> {
    const pedidos = await this.pedidoModel.find();
    return pedidos;
  }

  async findOne(id: string | number): Promise<Pedido> {
    const pedido = await this.pedidoModel.findById(id)
    .populate('cliente', 'nombre email telefono');
    if (!pedido) {
      throw new NotFoundException(`Pedido con ID ${id} no encontrado`);
    }
    return pedido;
  }

  async update(id: string | number, updatePedidoDto: UpdatePedidoDto): Promise<Pedido> {
    const pedido = await this.pedidoModel.findByIdAndUpdate(id, updatePedidoDto, { new: true })
    .populate('cliente', 'nombre email telefono');
    if (!pedido) {
      throw new NotFoundException(`Pedido con ID ${id} no encontrado`);
    }
    return pedido;
  }

  async remove(id: string | number): Promise<void> {
    const result = await this.pedidoModel.findByIdAndDelete(id);
    if (!result) {
      throw new NotFoundException(`Pedido con ID ${id} no encontrado`);
    }
  }
}
