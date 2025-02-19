import {
  Body,
  Controller,
  Delete,
  Get,
  NotFoundException,
  Param,
  Patch,
  Req,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { UpdateUserDto } from './dto/update-user.dto';
import { Roles } from 'src/auth/decorators/decorator';
import { UserRole } from './user.entity';
import { RolesGuard } from 'src/auth/guards/roles.guard';

@Controller('users')
// @UseGuards(AuthGuard)
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Get()
  @UseGuards(RolesGuard)
  @Roles(UserRole.ADMIN)
  findAll() {
    return this.usersService.findAll();
  }

  @Get(':id')
  async findOne(@Param('id') id: string, @Req() req) {
    const userId = parseInt(id, 10);

    if (req.user.role !== UserRole.ADMIN && req.user.id !== userId) {
      throw new UnauthorizedException('You can only view your own profile');
    }

    const user = await this.usersService.findOne(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return user;
  }

  @Patch(':id')
  async update(
    @Param('id') id: string,
    @Body() updateUserDto: UpdateUserDto,
    @Req() req,
  ) {
    const userId = parseInt(id, 10);

    if (req.user.role !== UserRole.ADMIN && req.user.id !== userId) {
      throw new UnauthorizedException('You can only update your own profile');
    }

    const user = await this.usersService.findOne(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    return this.usersService.update(userId, updateUserDto);
  }

  @Delete(':id')
  @UseGuards(RolesGuard)
  @Roles(UserRole.ADMIN)
  async remove(@Param('id') id: string) {
    const userId = parseInt(id, 10);
    const user = await this.usersService.findOne(userId);

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return this.usersService.remove(userId);
  }
}
