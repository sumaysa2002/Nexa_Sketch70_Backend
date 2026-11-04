import { sql, type SQL } from "drizzle-orm";
import { users } from "../db/schema.js";

/* ============================================================
   จัดการอีเมลให้เป็นรูปแบบเดียวกันทั้งระบบ
   - ตัดช่องว่างหน้า/หลัง + แปลงเป็นตัวพิมพ์เล็ก
============================================================ */

const MAX_EMAIL_LENGTH = 254; // ตาม RFC 5321
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/// แปลงอีเมลเป็นรูปแบบมาตรฐาน (ใช้กับค่าที่ตรวจแล้วว่าเป็น string)
export const normalizeEmail = (email: string): string => email.trim().toLowerCase();

/// รับค่าจาก client >> คืนอีเมลที่ normalize แล้ว หรือ null ถ้ารูปแบบไม่ถูกต้อง
export function parseEmail(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const email = normalizeEmail(value);
  if (!email || email.length > MAX_EMAIL_LENGTH || !EMAIL_RE.test(email)) return null;
  return email;
}

/// เงื่อนไข WHERE lower(users.email) = email (ใช้ unique index users_email_lower_idx)
export const userEmailEquals = (email: string): SQL =>
  sql`lower(${users.email}) = ${normalizeEmail(email)}`;