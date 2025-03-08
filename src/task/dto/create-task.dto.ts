import {
  IsNotEmpty,
  IsOptional,
  IsEnum,
  IsBoolean,
  IsString,
} from 'class-validator';
import { TaskPriority } from '../entities/task.entity';

export class CreateTaskDto {
  @IsNotEmpty()
  @IsString()
  title: string;

  @IsString()
  description: string;

  @IsBoolean()
  completed: boolean;

  @IsEnum(TaskPriority)
  priority: TaskPriority;
}
