import { Router } from "express";
import { auth, requireAdmin, type AuthRequest } from "../middleware/auth.js";
import { projects, projectMembers, projectHistory, users, usersHistory, points, pointHistory } from "../db/schema.js";
import type { NewProject, Project } from "../db/schema.js";
import { db } from "../db/index.js";
import { sql } from "drizzle-orm";
import type { Request, Response } from "express";
import { eq, asc, desc, and, inArray} from "drizzle-orm";
import { emptyToNull, toNumericOrNull, toIntOrNull, parseId } from "../helper/null.js";
import { getProjectCreatorId, getProjectAccess, activeGroupUserIds, everApprovedByAdmin } from "../helper/project_access.js";
import path from "path";
import fs from "fs";


const taskRouter = Router();

/* ============================================================
   ตรวจสอบข้อมูลโครงการ
============================================================ */

/// error ที่เกิดจากข้อมูลที่ client ส่งมา (ตอบ 400)
class BadInput extends Error {}

/// ตรวจและทำความสะอาดข้อมูลโครงการ (create_project และ sync_projects)
function cleanProjectInput(p: any) {
  if (!p || typeof p !== "object") throw new BadInput("ข้อมูลโครงการไม่ถูกต้อง");

  const projectName = typeof p.project_name === "string" ? p.project_name.trim() : "";
  if (!projectName || projectName.length > 500) throw new BadInput("ชื่อโครงการไม่ถูกต้อง");

  const text = (v: unknown, field: string, max = 5000) => {
    const r = emptyToNull(v);
    if (r === undefined || r === null) return r;
    if (typeof r !== "string" || r.length > max) throw new BadInput(`ข้อมูลฟิลด์ "${field}" ไม่ถูกต้อง`);
    return r;
  };

  const date = (v: unknown, field: string) => {
    const r = text(v, field, 50);
    if (typeof r === "string" && Number.isNaN(Date.parse(r))) {
      throw new BadInput(`ข้อมูลฟิลด์ "${field}" ไม่ใช่รูปแบบวันที่`);
    }
    return r;
  };

  let gsdNum: number | null;
  try {
    gsdNum = toIntOrNull(p.gsd_num, "GSD");
  } catch (e) {
    throw new BadInput((e as Error).message);
  }

  return {
    name_project_id:    text(p.name_project_id, "name_project_id", 200),
    project_name:       projectName,
    project_details:    text(p.project_details, "project_details"),
    province:           text(p.province, "province", 1000),

    sensor:             text(p.sensor, "sensor", 200),
    gsd_num:            gsdNum,
    gsd_unit:           text(p.gsd_unit, "gsd_unit", 50),

    survey_main:        text(p.survey_main, "survey_main", 200),
    survey_sub:         text(p.survey_sub, "survey_sub", 200),

    project_start_date: date(p.project_start_date, "project_start_date"),
    project_end_date:   date(p.project_end_date, "project_end_date"),

    project_note:       text(p.project_note, "project_note"),
  };
}

/// สมาชิกที่เพิ่มได้ต้องเป็น user ที่อยู่ในกลุ่มของ admin เท่านั้น
async function filterMemberIds(adminId: number, raw: unknown, strict: boolean): Promise<number[]> {
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw) || raw.length > 500) throw new BadInput("สมาชิกไม่ถูกต้อง");

  const ids = [...new Set(raw.map(Number))];
  if (strict && ids.some((n) => !Number.isInteger(n) || n <= 0)) {
    throw new BadInput("สมาชิกไม่ถูกต้อง");
  }
  const clean = ids.filter((n) => Number.isInteger(n) && n > 0);
  if (clean.length === 0) return [];

  // admin เจ้าของโครงการเลือกตัวเองเป็นสมาชิกได้
  const includeSelf = clean.includes(adminId);
  const others = clean.filter((n) => n !== adminId);

  // สมาชิกคนอื่นต้องเป็น user ที่อยู่ในกลุ่มของ admin
  const rows = others.length === 0 ? [] : await db
    .select({ id: users.id })
    .from(users)
    .where(
      and(
        inArray(users.id, others),
        eq(users.admin, String(adminId)),
        eq(users.status, "user")
      )
    );

  const valid = [...(includeSelf ? [adminId] : []), ...rows.map((r) => r.id)];
  if (strict && valid.length !== ids.length) {
    throw new BadInput("มีสมาชิกที่คุณไม่ได้อนุมัติสมาชิก");
  }
  return valid;
}


/// ─── รายชื่อสมาชิกใหม่ตอนแก้ไขโครงการ (ทั้ง admin เจ้าของและ Editor) ──────────
// project_members เก็บทั้ง "สมาชิกปัจจุบัน" และ "อดีตสมาชิก" (ถูกถอนอนุมัติแล้ว) ไว้เป็นประวัติผู้จัดทำ
// - เพิ่มได้เฉพาะ user ที่ยังอนุมัติอยู่ในกลุ่มของ admin เจ้าของ (หรือตัว admin เอง)
// - อดีตสมาชิกที่อยู่ในโครงการอยู่แล้ว: คงไว้ได้ (ไม่มีสิทธิ์แก้ไข เพราะ getProjectAccess ตรวจสถานะ)
//     · Editor ลบอดีตสมาชิกออกไม่ได้ (ไม่ส่งมาก็ยังคงอยู่) >> กันประวัติหาย
//     · admin เจ้าของโครงการลบออกได้ ถ้าตั้งใจไม่ส่งมา
// - อดีตสมาชิกกลุ่มที่ไม่เคยอยู่ในโครงการนี้ (เช่น ค่าค้างจาก cache) >> ตัดทิ้งเงียบๆ
// - คนนอกกลุ่ม / ยังไม่อนุมัติ / admin คนอื่น >> 400
async function resolveMemberUpdate(
  projectId: number,
  creatorId: number,
  raw: unknown,
  isOwnerAdmin: boolean
): Promise<number[]> {
  if (raw !== null && (!Array.isArray(raw) || raw.length > 500)) throw new BadInput("สมาชิกไม่ถูกต้อง");

  const ids = raw === null ? [] : [...new Set((raw as unknown[]).map(Number))];
  if (ids.some((n) => !Number.isInteger(n) || n <= 0)) throw new BadInput("สมาชิกไม่ถูกต้อง");

  // อดีตสมาชิกที่อยู่ในโครงการนี้ตอนนี้ (ไม่ active แต่เคยได้รับอนุมัติจาก admin เจ้าของ)
  const currentIds = (await db
    .select({ user_id: projectMembers.user_id })
    .from(projectMembers)
    .where(eq(projectMembers.project_id, projectId))
  ).map((r) => r.user_id);

  const allIds     = [...new Set([...ids, ...currentIds])];
  const active     = await activeGroupUserIds(creatorId, allIds);
  const everInGrp  = await everApprovedByAdmin(creatorId, allIds.filter((id) => !active.has(id)));
  const historical = new Set(currentIds.filter((id) => !active.has(id) && everInGrp.has(id)));

  const keep = new Set<number>();
  for (const id of ids) {
    if (active.has(id) || historical.has(id)) keep.add(id);
    else if (!everInGrp.has(id)) throw new BadInput("มีสมาชิกที่ไม่ได้รับการอนุมัติจากผู้ดูแลโครงการนี้");
    // อดีตสมาชิกกลุ่มที่ไม่เคยอยู่โครงการนี้ >> ข้าม
  }

  // Editor ไม่มีสิทธิ์ลบประวัติอดีตสมาชิก
  if (!isOwnerAdmin) historical.forEach((id) => keep.add(id));

  return [...keep];
}


/* ============================================================
   Idempotency (client_uuid)
============================================================ */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/// ── ตรวจ client_uuid (ไม่ส่งมา = null) ──
function parseClientUuid(value: unknown): string | null {
  const v = emptyToNull(value);
  if (v === undefined || v === null) return null;
  if (typeof v !== "string" || !UUID_RE.test(v)) throw new BadInput("client_uuid ไม่ถูกต้อง");
  return v.toLowerCase();
}

/// ── error จาก Postgres ว่าชน unique constraint ──
function isUniqueViolation(e: any): boolean {
  return e?.code === "23505" || e?.cause?.code === "23505";
}

/// ── หาโครงการที่สร้างไปแล้วด้วย client_uuid เดียวกัน ─────────────
async function findProjectByClientUuid(clientUuid: string, userId: number) {
  const [row] = await db
    .select()
    .from(projects)
    .where(eq(projects.client_uuid, clientUuid))
    .limit(1);

  if (!row) return null;
  const creatorId = await getProjectCreatorId(row.id);
  if (creatorId !== userId) return "mismatch" as const; // "mismatch" ถ้า uuid นี้เป็นของ admin คนอื่น
  return row;
}

/// ── สร้างโครงการ 1 รายการ (create_project และ sync_projects) ถ้าเคยสร้างด้วย client_uuid นี้แล้ว >> คืนโครงการเดิม ไม่สร้างซ้ำ ─────────────
async function createProjectIdempotent(
  userId: number,
  input: ReturnType<typeof cleanProjectInput>,
  memberIds: number[],
  clientUuid: string | null,
): Promise<{ project: Project; existed: boolean }> {

  if (clientUuid) {
    const existing = await findProjectByClientUuid(clientUuid, userId);
    if (existing === "mismatch") throw new BadInput("client_uuid ซ้ำกับข้อมูลอื่น");
    if (existing) return { project: existing, existed: true };
  }

  try {
    const project = await db.transaction(async (tx) => {
      const [newProject] = await tx
        .insert(projects)
        .values({ ...input, client_uuid: clientUuid } satisfies Partial<NewProject>)
        .returning();

      if (!newProject) throw new Error("สร้างโครงการไม่สำเร็จ");

      await tx.insert(projectHistory).values({
        project_id:           newProject.id,
        project_user_creator: userId,
        project_time_created: sql`now()`,
      });

      if (memberIds.length > 0) {
        await tx.insert(projectMembers).values(
          memberIds.map((uid) => ({
            project_id:       newProject.id,
            user_id:          uid,
            time_add_members: sql`now()`,
          }))
        );
      }

      return newProject;
    });
    return { project, existed: false };

  } catch (e) {
    // request ซ้ำมาพร้อมกัน >> อีกตัวสร้างไปแล้ว >> คืนตัวนั้น
    if (clientUuid && isUniqueViolation(e)) {
      const existing = await findProjectByClientUuid(clientUuid, userId);
      if (existing && existing !== "mismatch") return { project: existing, existed: true };
    }
    throw e;
  }
}




/* ============================================================
   ส่วนจัดการข้อมูล Project
============================================================ */

/// ── สร้างโครงการใหม่ (admin เท่านั้นที่สร้างได้) ──────────────────────────────────────
taskRouter.post("/create_project", auth, requireAdmin, async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.user!;

    const input      = cleanProjectInput(req.body);
    const clientUuid = parseClientUuid(req.body.client_uuid);
    const memberIds  = await filterMemberIds(userId, req.body.member_ids, true);

    const { project } = await createProjectIdempotent(userId, input, memberIds, clientUuid);

    res.status(201).json(project);
  } catch (e) {
    if (e instanceof BadInput) return res.status(400).json({ error: e.message });
    console.error("[POST /create_project] error:", e);
    res.status(500).json({ error: "สร้างโครงการไม่สำเร็จ" });
  }
});



/// ── ดึงโครงการทั้งหมด แยกตาม Admin (เรียงจากใหม่ >> เก่า) ────────────────────────────
taskRouter.get("/projects", auth, async (req: AuthRequest, res: Response) => {
  try {

    const userId = req.user!;

    // ตรวจสอบว่า User เป็น Admin หรือไม่
    const [currentUser] = await db
      .select({ status: users.status })
      .from(users)
      .where(eq(users.id, userId));

    const isAdmin = currentUser?.status === 'admin';

    let allProjects;

    // ── ถ้าเป็น Admin >> ดึงโครงการที่ Admin นี้เป็นผู้สร้าง ──────
    if (isAdmin) {
      allProjects = await db
        .select({
          id:                   projects.id,
          name_project_id:      projects.name_project_id,
          project_name:         projects.project_name,
          project_details:      projects.project_details,
          province:             projects.province,
          sensor:               projects.sensor,
          gsd_num:              projects.gsd_num,
          gsd_unit:             projects.gsd_unit,
          survey_main:          projects.survey_main,
          survey_sub:           projects.survey_sub,
          project_start_date:   projects.project_start_date,
          project_end_date:     projects.project_end_date,
          project_note:         projects.project_note,
          project_time_created: projectHistory.project_time_created,
          project_user_creator: projectHistory.project_user_creator,
        })
        .from(projects)
        .leftJoin(projectHistory, eq(projectHistory.project_id, projects.id))
        .where(eq(projectHistory.project_user_creator, userId))
        .orderBy(desc(projectHistory.project_time_created));

    } else {

      // ── ถ้าเป็น User >> ดึงโครงการทั้งหมดของ Admin กลุ่มเดียวกัน  ──────
      // 1. ดึง admin ของ user นี้
      const [currentUserFull] = await db
        .select({ admin: users.admin })
        .from(users)
        .where(eq(users.id, userId));

      // แปลง Admin ID จาก String เป็น Number
      const adminId = currentUserFull?.admin
        ? parseInt(currentUserFull.admin)
        : null;

      // ถ้า User ยังไม่ได้อยู่ในกลุ่ม Admin >> ไม่มีโครงการ
      if (!adminId) {
        return res.status(200).json([]);
      }

      // 2. ดึงโครงการทั้งหมดที่ admin นี้สร้าง
      allProjects = await db
        .select({
          id:                   projects.id,
          name_project_id:      projects.name_project_id,
          project_name:         projects.project_name,
          project_details:      projects.project_details,
          province:             projects.province,
          sensor:               projects.sensor,
          gsd_num:              projects.gsd_num,
          gsd_unit:             projects.gsd_unit,
          survey_main:          projects.survey_main,
          survey_sub:           projects.survey_sub,
          project_start_date:   projects.project_start_date,
          project_end_date:     projects.project_end_date,
          project_note:         projects.project_note,
          project_time_created: projectHistory.project_time_created,
          project_user_creator: projectHistory.project_user_creator,
        })
        .from(projects)
        .leftJoin(projectHistory, eq(projectHistory.project_id, projects.id))
        .where(eq(projectHistory.project_user_creator, adminId))
        .orderBy(desc(projectHistory.project_time_created));
    }

    // ดึงสมาชิกเฉพาะโครงการที่ส่งกลับ และเฉพาะคนที่ยังอยู่ในกลุ่ม (ตัดคนที่ถูกถอนอนุมัติ)
    const projectIds = allProjects.map((p) => p.id);
    const creatorOf  = new Map(allProjects.map((p) => [p.id, p.project_user_creator]));

    const memberRows = projectIds.length === 0 ? [] : await db
      .select({
        project_id: projectMembers.project_id,
        user_id:    projectMembers.user_id,
        status:     users.status,
        admin:      users.admin,
      })
      .from(projectMembers)
      .innerJoin(users, eq(users.id, projectMembers.user_id))
      .where(inArray(projectMembers.project_id, projectIds));

    // ประวัติการอนุมัติ: (user_id, admin) คู่ไหนเคยอนุมัติกันมาแล้ว >> อดีตสมาชิกยังแสดงในรายชื่อ
    const memberUserIds = [...new Set(memberRows.map((m) => m.user_id))];
    const approvals = memberUserIds.length === 0 ? [] : await db
      .select({ user_id: usersHistory.user_id, admin_id: usersHistory.admin_approved_user })
      .from(usersHistory)
      .where(and(
        inArray(usersHistory.user_id, memberUserIds),
        sql`${usersHistory.admin_approved_user} IS NOT NULL`
      ));
    const approvedPair = new Set(approvals.map((a) => `${a.user_id}:${a.admin_id}`));

    // สมาชิกที่แสดง = admin เจ้าของ + สมาชิกปัจจุบัน + อดีตสมาชิกของกลุ่มนี้ (ตัดคนนอกกลุ่มที่ค้างจากข้อมูลเก่า)
    const allMembers = memberRows.filter((m) => {
      const creator = creatorOf.get(m.project_id);
      return m.user_id === creator
        || (m.status === "user" && m.admin === String(creator))
        || approvedPair.has(`${m.user_id}:${creator}`);
    });

    const result = allProjects.map((project) => {

      // หา Member ของแต่ละ Project
      const memberIds = allMembers
        .filter((m) => m.project_id === project.id)
        .map((m) => m.user_id);

      // คำนวณ User Role
      const user_role = isAdmin
          ? 'Editor'
          : memberIds.includes(userId) ? 'Editor' : 'Viewer';

      return { ...project, member_ids: memberIds, user_role };
    });

    res.status(200).json(result);
  } catch (e) {
    console.error("[GET /projects] error:", e);
    res.status(500).json({ error: "ดึงข้อมูลโครงการไม่สำเร็จ" });
  }
});


/// ── อัปเดทข้อมูลโครงการ ────────────
taskRouter.put("/update_project/:id", auth, async (req: AuthRequest, res: Response) => {
  try {
    const userId   = req.user!;
    const projectId = parseId(req.params.id);

    if (projectId === null) {
      return res.status(400).json({ error: "projectId ไม่ถูกต้อง" });
    }

    // ตรวจสอบสิทธิ์แก้ไข (admin เจ้าของ หรือ Editor ที่ยังอยู่ในกลุ่ม)
    const access = await getProjectAccess(userId, projectId);
    if (!access) {
      return res.status(404).json({ error: "ไม่พบโครงการที่ต้องการแก้ไข" });
    }
    if (!access.canEdit) {
      return res.status(403).json({ error: "คุณไม่มีสิทธิ์แก้ไขโครงการนี้" });
    }

    const {
      name_project_id,
      project_name,
      project_details,
      province,
      sensor,
      gsd_num,
      gsd_unit,
      survey_main,
      survey_sub,
      project_start_date,
      project_end_date,
      project_note,
      member_ids,
    } = req.body;

    // ไม่ส่ง member_ids มา = ไม่แก้รายชื่อสมาชิก
    const newMemberIds = member_ids === undefined
      ? null
      : await resolveMemberUpdate(projectId, access.creatorId, member_ids, access.isOwnerAdmin);

    const result = await db.transaction(async (tx) => {

      // Update ตาราง projects
      const [updatedProject] = await tx
        .update(projects)
        .set({
          name_project_id:    emptyToNull(name_project_id),
          project_name,
          project_details:    emptyToNull(project_details),
          province:            emptyToNull(province),
          sensor:              emptyToNull(sensor),
          gsd_num:             toIntOrNull(gsd_num, "GSD"),
          gsd_unit:            emptyToNull(gsd_unit),
          survey_main:         emptyToNull(survey_main),
          survey_sub:          emptyToNull(survey_sub),
          project_start_date:  emptyToNull(project_start_date),
          project_end_date:    emptyToNull(project_end_date),
          project_note:        emptyToNull(project_note),
        })
        .where(eq(projects.id, projectId))
        .returning();

      if (!updatedProject) throw new Error("ไม่พบโครงการที่ต้องการแก้ไข");

      // ลบ members เดิมออก แล้ว insert ใหม่ (เฉพาะเมื่อส่ง member_ids มา)
      if (newMemberIds !== null) {
        await tx
          .delete(projectMembers)
          .where(eq(projectMembers.project_id, projectId));
      }

      if (newMemberIds !== null && newMemberIds.length > 0) {
        await tx.insert(projectMembers).values(
          newMemberIds.map((uid) => ({
            project_id:   projectId,
            user_id:      uid,
            time_add_members: sql`now()`,
          }))
        );
      }

      // Insert project_history
      await tx.insert(projectHistory).values({
        project_id:           projectId,
        project_user_updated: userId,
        project_time_updated: sql`now()`,
      });

      return updatedProject;
    });

    res.status(200).json(result);
  } catch (e) {
    if (e instanceof BadInput) return res.status(400).json({ error: e.message });
    console.error("[PUT /update_project] error:", e);
    res.status(500).json({ error: "แก้ไขโครงการไม่สำเร็จ" });
  }
});


/// ── ลบโครงการ (admin เท่านั้นที่ลบได้) >> ใช้ id project ในการลบ ────────────
taskRouter.delete("/delete_project/:id", auth, async (req: AuthRequest, res: Response) => {
  try {
    const userId    = req.user!;
    const projectId = parseId(req.params.id);

    if (projectId === null) {
      return res.status(400).json({ error: "projectId ไม่ถูกต้อง" });
    }

    // ต้องเป็น admin เจ้าของโครงการเท่านั้นถึงลบได้
    const creatorId = await getProjectCreatorId(projectId);
    if (creatorId === null) {
      return res.status(404).json({ error: "ไม่พบโครงการที่ต้องการลบ" });
    }

    const [currentUser] = await db
      .select({ id: users.id, status: users.status })
      .from(users)
      .where(eq(users.id, userId));

    if (!currentUser || currentUser.status !== "admin" || creatorId !== userId) {
      return res.status(403).json({ error: "เฉพาะผู้ดูแลโครงการเท่านั้นที่สามารถลบโครงการได้" });
    }

    await db.transaction(async (tx) => {

      // 1. ดึง point ทั้งหมดของโครงการ
      const allPoints = await tx
        .select({ id: points.id })
        .from(points)
        .where(eq(points.project_id, projectId));

      // Insert point_history
      if (allPoints.length > 0) {
        await tx.insert(pointHistory).values(
          allPoints.map((p) => ({
            project_id:        projectId,
            point_id:          p.id,
            point_user_delete: userId,
            point_time_delete: sql`now()`,
          }))
        );

        // ลบ points ทั้งหมดของโครงการ
        await tx
          .delete(points)
          .where(eq(points.project_id, projectId));
      }

      // 2. ลบ project_members
      await tx
        .delete(projectMembers)
        .where(eq(projectMembers.project_id, projectId));

      // Insert project_history
      await tx.insert(projectHistory).values({
        project_id:          projectId,
        project_user_delete: userId,
        project_time_delete: sql`now()`,
      });

      // 3. ลบ projects
      await tx
        .delete(projects)
        .where(eq(projects.id, projectId));
    });

    // 4. ลบโฟเดอร์รูปภาพทั้งหมดของโครงการ
    const projectDir = path.join("uploads", "point", String(projectId));
    if (fs.existsSync(projectDir)) {
      fs.rmSync(projectDir, { recursive: true, force: true });
      console.log(`[DELETE] removed dir: ${projectDir}`);
    }

    res.status(200).json({ message: "ลบโครงการสำเร็จ" });
  } catch (e) {
    console.error("[DELETE /delete_project] error:", e);
    res.status(500).json({ error: "ลบโครงการไม่สำเร็จ" });
  }
});


/// ── sync โครงการที่สร้างขณะ offline ขึ้น server ────────────────────────────
taskRouter.post("/sync_projects", auth, requireAdmin, async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.user!;
    const list   = req.body;

    if (!Array.isArray(list) || list.length > 50) {
      return res.status(400).json({ error: "ข้อมูลที่ส่งมาไม่ถูกต้อง" });
    }

    // ── client รุ่นเก่า (ไม่ส่ง client_uuid)
    if (list.every((p: any) => !p?.client_uuid)) {
      const prepared: { input: ReturnType<typeof cleanProjectInput>; memberIds: number[] }[] = [];
      for (const p of list) {
        prepared.push({
          input:     cleanProjectInput(p),
          memberIds: await filterMemberIds(userId, p?.member_ids, false),
        });
      }

      const legacy = await db.transaction(async (tx) => {
        const out = [];
        for (const { input, memberIds } of prepared) {
          const [newProject] = await tx
            .insert(projects)
            .values(input satisfies Partial<NewProject>)
            .returning();
          if (!newProject) throw new Error("sync โครงการไม่สำเร็จ");

          await tx.insert(projectHistory).values({
            project_id:           newProject.id,
            project_user_creator: userId,
            project_time_created: sql`now()`,
          });

          if (memberIds.length > 0) {
            await tx.insert(projectMembers).values(
              memberIds.map((uid) => ({
                project_id:       newProject.id,
                user_id:          uid,
                time_add_members: sql`now()`,
              }))
            );
          }
          out.push(newProject);
        }
        return out;
      });

      return res.status(201).json(legacy);
    }

    const results = [];

    for (const p of list) {
      const rawUuid = typeof p?.client_uuid === "string" ? p.client_uuid : null;
      try {
        const input      = cleanProjectInput(p);
        const clientUuid = parseClientUuid(p?.client_uuid);
        const memberIds  = await filterMemberIds(userId, p?.member_ids, false);

        const { project, existed } = await createProjectIdempotent(userId, input, memberIds, clientUuid);
        results.push({ client_uuid: rawUuid, status: existed ? "exists" : "created", project });

      } catch (e) {
        if (e instanceof BadInput) {
          results.push({ client_uuid: rawUuid, status: "error", error: e.message });
          continue;
        }
        throw e;
      }
    }

    res.status(200).json({ results });
  } catch (e) {
    if (e instanceof BadInput) return res.status(400).json({ error: e.message });
    console.error("[POST /sync_projects] error:", e);
    res.status(500).json({ error: "sync โครงการไม่สำเร็จ" });
  }
});


export default taskRouter;