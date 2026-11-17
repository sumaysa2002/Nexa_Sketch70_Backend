import { and, eq, isNull, sql } from "drizzle-orm";
import { db } from "../db/index.js";
import { points, pointHistory } from "../db/schema.js";

type Tx = Parameters<Parameters<typeof db.transaction>[0]>[0];

/* ============================================================
   ประวัติทุกหมุด (point_history) >> ตอนลบ / กู้คืน (ทั้งโครงการ)
   - บันทึกใน point_history ทุกหมุด
   - บันทึกเฉพาะหมุดที่ยังไม่ถูกลบ (deleted_at IS NULL)
============================================================ */

/// ── ลบโครงการ >> บันทึก point_user_delete / point_time_delete ให้ทุกหมุดที่ยังไม่ถูกลบในโครงการ ──
export async function logPointsDeletedWithProject(tx: Tx, projectId: number, userId: number): Promise<void> {
  await tx.execute(sql`
    INSERT INTO ${pointHistory} (project_id, point_id, point_user_delete, point_time_delete)
    SELECT ${points.project_id}, ${points.id}, ${userId}::int, now()
    FROM ${points}
    WHERE ${and(eq(points.project_id, projectId), isNull(points.deleted_at))}
  `);
}

/// ── กู้คืนโครงการ >> บันทึก point_user_restore / point_time_restore ให้ทุกหมุดที่ยังไม่ถูกลบในโครงการ ──
export async function logPointsRestoredWithProject(tx: Tx, projectId: number, userId: number): Promise<void> {
  await tx.execute(sql`
    INSERT INTO ${pointHistory} (project_id, point_id, point_user_restore, point_time_restore)
    SELECT ${points.project_id}, ${points.id}, ${userId}::int, now()
    FROM ${points}
    WHERE ${and(eq(points.project_id, projectId), isNull(points.deleted_at))}
  `);
}