import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Task } from './entities/task.entity';
import { Repository } from 'typeorm';
import { CreateTaskDto } from './dto/create-task.dto';
import { UpdateTaskDto } from './dto/update-task.dto';
import { User } from 'src/users/user.entity';

@Injectable()
export class TaskService {
  constructor(
    @InjectRepository(Task) private taskRepository: Repository<Task>,
  ) {}

  async createTask(createTaskDto: CreateTaskDto, user: User): Promise<Task> {
    const task = this.taskRepository.create({
      ...createTaskDto,
      user,
    });
    return await this.taskRepository.save(task);
  }

  async getTasks(
    user: User,
    page: number = 1,
    limit: number = 10,
    search?: string,
    status?: boolean,
    priority?: string,
    sortBy?: string,
    sortOrder: 'ASC' | 'DESC' = 'DESC',
  ): Promise<{ data: Task[]; total: number }> {
    const query = this.taskRepository
      .createQueryBuilder('task')
      .where('task.userId = :userId', { userId: user.id });

    if (search) {
      query.andWhere(
        '(task.title ILIKE :search OR task.description ILIKE :search)',
        { search: `%${search}%` },
      );
    }

    if (status !== undefined) {
      query.andWhere('task.completed = :status', { status });
    }

    if (priority) {
      query.andWhere('task.priority = :priority', { priority });
    }

    if (sortBy) {
      query.orderBy(`task.${sortBy}`, sortOrder);
    } else {
      query.orderBy('task.createdAt', 'DESC');
    }

    const [task, total] = await query
      .skip((page - 1) * limit)
      .take(limit)
      .getManyAndCount();

    return { data: task, total };
  }

  // ✅ Get Single Task by ID
  async getTaskById(id: number, user: User): Promise<Task> {
    const task = await this.taskRepository.findOne({ where: { id, user } });
    if (!task) throw new NotFoundException('Task not found');
    return task;
  }

  // ✅ Update Task
  async updateTask(
    id: number,
    updateTaskDto: UpdateTaskDto,
    user: User,
  ): Promise<Task> {
    const task = await this.getTaskById(id, user);
    Object.assign(task, updateTaskDto);
    return await this.taskRepository.save(task);
  }

  // ✅ Delete Task
  async deleteTask(id: number, user: User): Promise<void> {
    const task = await this.getTaskById(id, user);
    await this.taskRepository.remove(task);
  }
}
