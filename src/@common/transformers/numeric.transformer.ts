import { ValueTransformer } from 'typeorm';


export class ColumnNumericTransformer implements ValueTransformer {
  to(data: number | null | undefined): number | null {
    if (data === null || data === undefined) {
      return null;
    }
    return data;
  }

  from(data: string | number | null | undefined): number | null {
    if (data === null || data === undefined) {
      return null;
    }

    if (typeof data === "number") {
      return data;
    }

    const parsed = parseFloat(data);
    if (Number.isNaN(parsed)) {
      return null;
    }
    return parsed;
  }
}
