import { sql, type AnyColumn } from "drizzle-orm";

/// ── ระยะเวลาที่เก็บข้อมูลไว้ในประวัติการลบ (วัน) ก่อนลบถาวร ──
export const TRASH_RETENTION_DAYS = 30;

/// ── เวลาที่จะถูกลบถาวร = deleted_at + 30 วัน ──
export const purgeAtSql = (deletedAt: AnyColumn) =>
  sql<string>`(${deletedAt} + make_interval(days => ${TRASH_RETENTION_DAYS}))`;

/// ── จำนวนวันที่เหลือ (ปัดขึ้น, ต่ำสุด 0) ──
export const daysLeftSql = (deletedAt: AnyColumn) =>
  sql<number>`GREATEST(0, CEIL(EXTRACT(EPOCH FROM (${deletedAt} + make_interval(days => ${TRASH_RETENTION_DAYS}) - now())) / 86400))::int`;

/// ── กู้คืน >> ยังไม่หมดเวลา 30 วัน ──
export const notExpiredSql = (deletedAt: AnyColumn) =>
  sql`${deletedAt} > now() - make_interval(days => ${TRASH_RETENTION_DAYS})`;

/// ── ลบถาวร >> หมดเวลา 30 วัน ──
export const expiredSql = (deletedAt: AnyColumn) =>
  sql`${deletedAt} <= now() - make_interval(days => ${TRASH_RETENTION_DAYS})`;