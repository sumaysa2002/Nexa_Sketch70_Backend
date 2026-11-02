// ─── text type ──────────────────────── 
export function emptyToNull(value: any) {
  if (value === undefined) return undefined;

  if (typeof value === "string") {
    const trimmed = value.trim();
    if (trimmed === "" || trimmed === "-") {
      return null;
    }
  }

  return value;
}

// ─── numeric type ──────────────────────── 
export function toNumericOrNull(value: any, fieldName: string): string | null {
  if (value === undefined || value === null) return null;
  const trimmed = String(value).trim();
  if (trimmed === "" || trimmed === "-") return null;

  if (!/^-?\d+(\.\d+)?$/.test(trimmed)) {
    throw new Error(`ข้อมูลฟิลด์ "${fieldName}" ไม่ใช่ตัวเลขที่ถูกต้อง: "${trimmed}"`);
  }
  return trimmed;
}

// ─── integer type ──────────────────────── 
export function toIntOrNull(value: any, fieldName: string): number | null {
  if (value === undefined || value === null) return null;
  const trimmed = String(value).trim();
  if (trimmed === "" || trimmed === "-") return null;

  if (!/^\d+$/.test(trimmed)) {
    throw new Error(`ข้อมูลฟิลด์ "${fieldName}" ไม่ใช่จำนวนเต็มที่ถูกต้อง: "${trimmed}"`);
  }
  return parseInt(trimmed, 10);
}

// ─── id จาก URL / body (กัน id ติดลบของข้อมูล offline) ────────────────────────
export function parseId(value: unknown): number | null {
  if (typeof value !== "string" && typeof value !== "number") return null;
  const str = String(value).trim();
  if (!/^\d{1,10}$/.test(str)) return null;
  const n = Number(str);
  return n >= 1 && n <= 2_147_483_647 ? n : null;
}