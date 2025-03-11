import {
  IsNotEmpty,
  IsEnum,
  IsBoolean,
  IsString,
  IsDate,
} from 'class-validator';
import { TaskPriority } from '../entities/task.entity';
import { Type } from 'class-transformer';

export class CreateTaskDto {
  @IsNotEmpty()
  @IsString()
  title: string;

  @IsString()
  description: string;

  @IsBoolean()
  completed: boolean;

  @IsNotEmpty()
  @IsDate()
  @Type(() => Date)
  dueDate: Date;

  @IsEnum(TaskPriority)
  priority: TaskPriority;
}
