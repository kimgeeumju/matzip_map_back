import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // 🔥 이 부분 추가
  app.enableCors({
    origin: 'http://localhost:5173', // Vite 프론트 주소
    credentials: true,
  });

  await app.listen(3030);
}
bootstrap();
