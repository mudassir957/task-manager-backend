import { IsOptional, IsEnum, IsBoolean, IsString } from 'class-validator';
import { TaskPriority } from '../entities/task.entity';

export class UpdateTaskDto {
  @IsOptional()
  @IsString()
  title?: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsOptional()
  @IsBoolean()
  completed?: boolean;

  @IsOptional()
  @IsEnum(TaskPriority)
  priority?: TaskPriority;
}
