import {
  Controller,
  Post,
  Get,
  Patch,
  Delete,
  Body,
  Param,
  Query,
  UseGuards,
} from '@nestjs/common';
import { TaskService } from './task.service';
import { CreateTaskDto } from './dto/create-task.dto';
import { UpdateTaskDto } from './dto/update-task.dto';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { User } from 'src/users/user.entity';
import { GetUser } from 'src/auth/decorators/get-user.decorator';

@Controller('tasks')
@UseGuards(JwtAuthGuard)
export class TaskController {
  constructor(private readonly taskService: TaskService) {}

  // ✅ Create Task
  @Post()
  createTask(@Body() createTaskDto: CreateTaskDto, @GetUser() user: User) {
    return this.taskService.createTask(createTaskDto, user);
  }

  // ✅ Get Tasks with Filtering, Sorting, Pagination
  @Get()
  getTasks(
    @GetUser() user: User,
    @Query('page') page: number = 1,
    @Query('limit') limit: number = 10,
    @Query('search') search?: string,
    @Query('status') status?: boolean,
    @Query('priority') priority?: string,
    @Query('sortBy') sortBy?: string,
    @Query('sortOrder') sortOrder: 'ASC' | 'DESC' = 'DESC',
  ) {
    return this.taskService.getTasks(
      user,
      page,
      limit,
      search,
      status,
      priority,
      sortBy,
      sortOrder,
    );
  }

  // ✅ Get Single Task
  @Get(':id')
  getTaskById(@Param('id') id: number, @GetUser() user: User) {
    return this.taskService.getTaskById(id, user);
  }

  // ✅ Update Task
  @Patch(':id')
  updateTask(
    @Param('id') id: number,
    @Body() updateTaskDto: UpdateTaskDto,
    @GetUser() user: User,
  ) {
    return this.taskService.updateTask(id, updateTaskDto, user);
  }

  // ✅ Delete Task
  @Delete(':id')
  deleteTask(@Param('id') id: number, @GetUser() user: User) {
    return this.taskService.deleteTask(id, user);
  }
}
