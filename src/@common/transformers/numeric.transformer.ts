// src/@common/transformers/numeric.transformer.ts
import { ValueTransformer } from 'typeorm';

/**
 * DB의 numeric/decimal 컬럼을 TypeScript에서 number로 다루기 위한 트랜스포머
 * - DB에서는 문자열("123.45")로 오고
 * - 코드에서는 number(123.45)로 사용하고 싶을 때 사용
 */
export class ColumnNumericTransformer implements ValueTransformer {
  // TypeScript -> DB 로 저장될 때
  to(data: number | null | undefined): number | null {
    if (data === null || data === undefined) {
      return null;
    }
    return data;
  }

  // DB -> TypeScript 로 읽어올 때
  from(data: string | number | null | undefined): number | null {
    if (data === null || data === undefined) {
      return null;
    }

    // 이미 숫자면 그대로
    if (typeof data === "number") {
      return data;
    }

    // 문자열이면 number로 변환
    const parsed = parseFloat(data);
    if (Number.isNaN(parsed)) {
      return null;
    }
    return parsed;
  }
}
