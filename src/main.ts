// src/main.ts
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  // 🔥 Nest 앱 생성
  const app = await NestFactory.create(AppModule);

  // 🔥 CORS 확실하게 열기
  app.enableCors({
    origin: [
      'http://localhost:5173',        // 로컬 개발용
      'https://kimgeeumju.github.io', // GitHub Pages (matzip_map 포함)
    ],
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS',
    allowedHeaders: 'Content-Type, Authorization',
  });

  const port = process.env.PORT || 3000;
  await app.listen(port);
  console.log(`🚀 Server running on port ${port}`);
}

bootstrap();
