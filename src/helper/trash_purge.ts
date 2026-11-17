import fs from "fs";
import path from "path";
import { and, inArray, isNotNull } from "drizzle-orm";
import { db } from "../db/index.js";
import { projects, points } from "../db/schema.js";

/* ============================================================
   ลบถาวร (ก่อนครบ 30 วัน) จากหน้าประวัติการลบ
   - ลบได้เฉพาะโครงการ/หมุดที่อยู่ในประวัติการลบเท่านั้น (deleted_at IS NOT NULL)
   - FK onDelete cascade >> ลบ points / point_data_json / project_members / ลบโฟลเดอร์รูป
============================================================ */

const POINT_ROOT = path.join("uploads", "point");

function removeDir(dir: string): void {
  try {
    if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
  } catch (e) {
    console.error(`[PURGE] remove folder failed: ${dir}`, e);
  }
}

/// ── ลบถาวรโครงการ ──
export async function purgeProjectsNow(ids: number[]): Promise<number[]> {
  if (ids.length === 0) return [];

  const rows = await db
    .delete(projects)
    .where(and(inArray(projects.id, ids), isNotNull(projects.deleted_at)))
    .returning({ id: projects.id });

  for (const { id } of rows) removeDir(path.join(POINT_ROOT, String(id)));
  return rows.map((r) => r.id);
}

/// ── ลบถาวรหมุดรังวัด ──
export async function purgePointsNow(ids: number[]): Promise<number[]> {
  if (ids.length === 0) return [];

  const rows = await db
    .delete(points)
    .where(and(inArray(points.id, ids), isNotNull(points.deleted_at)))
    .returning({ id: points.id, project_id: points.project_id });

  for (const r of rows) removeDir(path.join(POINT_ROOT, String(r.project_id), String(r.id)));
  return rows.map((r) => r.id);
}