import { and, asc, eq, inArray, isNull, sql } from "drizzle-orm";
import { db } from "../db/index.js";
import { projectHistory, projectMembers, projects, users, usersHistory } from "../db/schema.js";

/* ============================================================
   สิทธิ์เข้าถึงโครงการ (ใช้ร่วมกันทั้ง task.ts และ point_task.ts)
   - admin เจ้าของโครงการ        >> ดูได้ + แก้ไขได้
   - user ในกลุ่มของ admin นั้น   >> ดูได้
       + เป็นสมาชิกโครงการ       >> แก้ไขได้
   - user ที่ถูกถอนอนุมัติ / อยู่กลุ่มอื่น / admin คนอื่น >> ไม่มีสิทธิ์ (แม้จะยังมีแถวค้างใน project_members ก็ตาม)
   
   โครงการที่อยู่ใน ประวัติการลบ
   - projects.deleted_at มีค่า >> ถือว่าไม่พบโครงการ
     เว้นแต่เรียกด้วย { includeDeleted: true } (ใช้เฉพาะหน้าประวัติการลบ / กู้คืน)
============================================================ */

export interface AccessOpts {
  includeDeleted?: boolean;
}

/// ─── หา admin ที่เป็นผู้สร้างโครงการ ──────────
export async function getProjectCreatorId(projectId: number, opts: AccessOpts = {}): Promise<number | null> {
  const [row] = await db
    .select({ project_user_creator: projectHistory.project_user_creator })
    .from(projectHistory)
    .innerJoin(projects, eq(projects.id, projectHistory.project_id))
    .where(
      and(
        eq(projectHistory.project_id, projectId),
        sql`${projectHistory.project_user_creator} IS NOT NULL`,
        opts.includeDeleted ? undefined : isNull(projects.deleted_at),
      )
    )
    .orderBy(asc(projectHistory.project_time_created))
    .limit(1);

  return row?.project_user_creator ?? null;
}

export interface ProjectAccess {
  creatorId: number;
  isOwnerAdmin: boolean;
  canView: boolean;
  canEdit: boolean;
}

/// ─── สิทธิ์ของ user ต่อโครงการ (null = ไม่พบโครงการ) ──────────
export async function getProjectAccess(
  userId: number,
  projectId: number,
  opts: AccessOpts = {},
): Promise<ProjectAccess | null> {
  const creatorId = await getProjectCreatorId(projectId, opts);
  if (creatorId === null) return null;

  const none: ProjectAccess = { creatorId, isOwnerAdmin: false, canView: false, canEdit: false };

  const [me] = await db
    .select({ id: users.id, status: users.status, admin: users.admin })
    .from(users)
    .where(eq(users.id, userId));

  if (!me) return none;

  // admin: เจ้าของโครงการ
  if (me.status === "admin") {
    const owner = me.id === creatorId;
    return { creatorId, isOwnerAdmin: owner, canView: owner, canEdit: owner };
  }

  // user: ได้รับอนุมัติจาก admin และเป็นสมาชิกโครงการ
  if (me.status !== "user" || me.admin !== String(creatorId)) return none;

  const [member] = await db
    .select({ id: projectMembers.id })
    .from(projectMembers)
    .where(and(eq(projectMembers.project_id, projectId), eq(projectMembers.user_id, userId)))
    .limit(1);

  return { creatorId, isOwnerAdmin: false, canView: true, canEdit: !!member };
}

export async function canViewProject(userId: number, projectId: number, opts: AccessOpts = {}): Promise<boolean> {
  return (await getProjectAccess(userId, projectId, opts))?.canView ?? false;
}

export async function canEditProject(userId: number, projectId: number, opts: AccessOpts = {}): Promise<boolean> {
  return (await getProjectAccess(userId, projectId, opts))?.canEdit ?? false;
}

/// ─── id ที่อยู่ในกลุ่มของ admin (ตัว admin เอง + user ที่อนุมัติแล้ว) ──────────
export async function activeGroupUserIds(adminId: number, ids: number[]): Promise<Set<number>> {
  const out = new Set<number>();
  const others = ids.filter((id) => id !== adminId);
  if (ids.includes(adminId)) out.add(adminId);
  if (others.length === 0) return out;

  const rows = await db
    .select({ id: users.id })
    .from(users)
    .where(and(inArray(users.id, others), eq(users.admin, String(adminId)), eq(users.status, "user")));

  rows.forEach((r) => out.add(r.id));
  return out;
}

/// ─── id ที่ "เคยได้รับอนุมัติ" จาก admin (รวมคนที่ถูกถอนอนุมัติไปแล้ว) ──────────
export async function everApprovedByAdmin(adminId: number, ids: number[]): Promise<Set<number>> {
  if (ids.length === 0) return new Set();
  const rows = await db
    .select({ user_id: usersHistory.user_id })
    .from(usersHistory)
    .where(and(inArray(usersHistory.user_id, ids), eq(usersHistory.admin_approved_user, adminId)));
  return new Set(rows.map((r) => r.user_id));
}