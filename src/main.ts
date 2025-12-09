// src/main.ts
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  // 🔥 여기서 아예 cors 옵션을 함께 넣어서 앱 생성
  const app = await NestFactory.create(AppModule, {
    cors: {
      origin: [
        'http://localhost:5173',        // 로컬 개발용
        'https://kimgeeumju.github.io', // 깃허브 페이지 origin
      ],
      methods: 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS',
      allowedHeaders: 'Content-Type, Authorization',
    },
  });

  const port = process.env.PORT || 3000;
  await app.listen(port);
  console.log(`🚀 Server running on port ${port}`);
}

bootstrap();
