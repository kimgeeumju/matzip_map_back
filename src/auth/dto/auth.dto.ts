import {
  IsString,
  Matches,
  MaxLength,
  MinLength,
  ValidateIf,
} from 'class-validator';

export class AuthDto {
  @IsString()
  @MinLength(6, {
    message: '올바른 이메일 형식이 아닙니다.',
  })
  @MaxLength(50, {
    message: '올바른 이메일 형식이 아닙니다.',
  })
  @Matches(/^[^\s@]+@[^\s@]+\.[^\s@]+$/, {
    message: '올바른 이메일 형식이 아닙니다.',
  })
  email: string;

  @IsString()
  @MinLength(8, {
    message: '이메일 또는 비밀번호가 일치하지 않습니다.',
  })
  @MaxLength(20)
  @Matches(/^[a-zA-z0-9]*$/, {
    message: '비밀번호가 영어 또는 숫자 조합이 아닙니다.',
  })
  password: string;
}
