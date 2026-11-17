import fs from "fs";
import path from "path";
import { and, eq, isNotNull } from "drizzle-orm";
import { db } from "../db/index.js";
import { projects, points } from "../db/schema.js";
import { expiredSql } from "../helper/trash.js";

const BATCH = 100;                       // ลบรอบละไม่เกินกี่รายการ
const INTERVAL_MS = 6 * 60 * 60 * 1000;  // ตรวจทุก 6 ชั่วโมง
let running = false;

/// ── ลบครบ 30 วัน ลบถาวร: โครงการ/หมุดที่อยู่ในประวัติการลบ ──
export async function purgeExpiredTrash(): Promise<void> {
  if (running) return;
  running = true;
  try {
    // 1) โครงการครบ 30 วัน >> ลบแถว FK onDelete cascade >> ลบ points / point_data_json / project_members / ลบโฟลเดอร์รูป
    const expiredProjects = await db
      .select({ id: projects.id })
      .from(projects)
      .where(and(isNotNull(projects.deleted_at), expiredSql(projects.deleted_at)))
      .limit(BATCH);

    for (const { id } of expiredProjects) {
      try {
        await db.delete(projects).where(eq(projects.id, id));
        const dir = path.join("uploads", "point", String(id));
        if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
        console.log(`[PURGE] project ${id}`);
      } catch (e) {
        console.error(`[PURGE] project ${id} failed:`, e);
      }
    }

    // 2) หมุดครบ 30 วัน (ลบหมุด ไม่ลบโครงการ)
    const expiredPoints = await db
      .select({ id: points.id, project_id: points.project_id })
      .from(points)
      .where(and(isNotNull(points.deleted_at), expiredSql(points.deleted_at)))
      .limit(BATCH);

    for (const p of expiredPoints) {
      try {
        await db.delete(points).where(eq(points.id, p.id));
        const dir = path.join("uploads", "point", String(p.project_id), String(p.id));
        if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
        console.log(`[PURGE] point ${p.id}`);
      } catch (e) {
        console.error(`[PURGE] point ${p.id} failed:`, e);
      }
    }
  } catch (e) {
    console.error("[PURGE] error:", e);
  } finally {
    running = false;
  }
}

/// ── เรียกครั้งเดียวตอนเซิร์ฟเวอร์เริ่มทำงาน: รันทันที แล้วรันซ้ำทุก 6 ชั่วโมง ──
export function startPurgeJob(): void {
  void purgeExpiredTrash();
  setInterval(() => void purgeExpiredTrash(), INTERVAL_MS).unref();
}