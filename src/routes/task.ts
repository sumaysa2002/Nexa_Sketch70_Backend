import { Router } from "express";
import { auth, type AuthRequest } from "../middleware/auth.js";
import { projects, projectMembers, projectHistory, users, points, pointHistory } from "../db/schema.js";
import type { NewProject } from "../db/schema.js";
import { db } from "../db/index.js";
import { sql } from "drizzle-orm";
import type { Request, Response } from "express";
import { eq, asc, desc, and} from "drizzle-orm";
import { emptyToNull, toNumericOrNull, toIntOrNull } from "../helper/null.js";
import path from "path";
import fs from "fs";


const taskRouter = Router();

/// ─── หา admin ที่เป็นผู้สร้างโครงการ (จาก project_history) ──────────
async function getProjectCreatorId(projectId: number): Promise<number | null> {
  const [row] = await db
    .select({ project_user_creator: projectHistory.project_user_creator })
    .from(projectHistory)
    .where(
      and(
        eq(projectHistory.project_id, projectId),
        sql`${projectHistory.project_user_creator} IS NOT NULL`
      )
    )
    .orderBy(asc(projectHistory.project_time_created))
    .limit(1);

  return row?.project_user_creator ?? null;
}


/* ============================================================
   ส่วนจัดการข้อมูล Project
============================================================ */

/// ── สร้างโครงการใหม่ (admin เท่านั้นที่สร้างได้) ──────────────────────────────────────
taskRouter.post("/create_project", auth, async (req: AuthRequest, res: Response) => {
  try {

    // id ของ user ที่ login
    const userId = req.user!;

    // ตรวจสอบว่าเป็น admin
    const [currentUser] = await db
      .select({ id: users.id, status: users.status })
      .from(users)
      .where(eq(users.id, userId));

    if (!currentUser || currentUser.status !== "admin") {
      return res.status(403).json({ error: "เฉพาะผู้ดูแลระบบเท่านั้นที่สามารถสร้างโครงการได้" });
    }

    // ข้อมูล project จาก Flutter
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
      member_ids, // array ของ user_id เช่น [2, 5, 7]
    } = req.body;

    const result = await db.transaction(async (tx) => {

      // Insert ตาราง projects
      const [newProject] = await tx
        .insert(projects)
        .values({
          name_project_id:     emptyToNull(name_project_id),
          project_name,
          project_details:     emptyToNull(project_details),
          province:            emptyToNull(province),
          sensor:              emptyToNull(sensor),
          gsd_num:             toIntOrNull(gsd_num, "GSD"),
          gsd_unit:            emptyToNull(gsd_unit),
          survey_main:         emptyToNull(survey_main),
          survey_sub:          emptyToNull(survey_sub),
          project_start_date:  emptyToNull(project_start_date),
          project_end_date:    emptyToNull(project_end_date),
          project_note:        emptyToNull(project_note),
        } satisfies Partial<NewProject>)
        .returning();

      if (!newProject) throw new Error("สร้างโครงการไม่สำเร็จ");

      // Insert ตาราง project_history
      await tx.insert(projectHistory).values({
        project_id:           newProject.id,
        project_user_creator: userId,
        project_time_created: sql`now()`,
      });

      // Insert ตาราง project_members (ถ้ามีสมาชิกในโครงการ)
      if (Array.isArray(member_ids) && member_ids.length > 0) {
        await tx.insert(projectMembers).values(
          member_ids.map((uid: number) => ({
            project_id:  newProject.id,
            user_id:     uid,
            time_add_members: sql`now()`,
          }))
        );
      }

      return newProject;
    });

    res.status(201).json(result);
  } catch (e) {
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

    // ดึงข้อมูลสมาชิกทั้งหมดในโครงการ
    const allMembers = await db
      .select({
        project_id: projectMembers.project_id,
        user_id:    projectMembers.user_id,
      })
      .from(projectMembers);

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
    const projectId = parseInt(req.params.id as string);

    if (isNaN(projectId)) {
      return res.status(400).json({ error: "projectId ไม่ถูกต้อง" });
    }

    // ตรวจสอบสิทธิ์แก้ไข
    const creatorId = await getProjectCreatorId(projectId);
    if (creatorId === null) {
      return res.status(404).json({ error: "ไม่พบโครงการที่ต้องการแก้ไข" });
    }

    const [currentUser] = await db
      .select({ id: users.id, status: users.status })
      .from(users)
      .where(eq(users.id, userId));

    const isOwnerAdmin = currentUser?.status === "admin" && creatorId === userId;

    let isEditorMember = false;
    if (!isOwnerAdmin) {
      const [member] = await db
        .select({ id: projectMembers.id })
        .from(projectMembers)
        .where(
          and(
            eq(projectMembers.project_id, projectId),
            eq(projectMembers.user_id, userId)
          )
        );
      isEditorMember = !!member;
    }

    if (!isOwnerAdmin && !isEditorMember) {
      return res.status(403).json({ error: "ไม่มีสิทธิ์แก้ไขโครงการนี้" });
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

      // ลบ members เดิมออก แล้ว insert ใหม่
      await tx
        .delete(projectMembers)
        .where(eq(projectMembers.project_id, projectId));

      if (Array.isArray(member_ids) && member_ids.length > 0) {
        await tx.insert(projectMembers).values(
          member_ids.map((uid: number) => ({
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
    console.error("[PUT /update_project] error:", e);
    res.status(500).json({ error: "แก้ไขโครงการไม่สำเร็จ" });
  }
});


/// ── ลบโครงการ (admin เท่านั้นที่ลบได้) >> ใช้ id project ในการลบ ────────────
taskRouter.delete("/delete_project/:id", auth, async (req: AuthRequest, res: Response) => {
  try {
    const userId    = req.user!;
    const projectId = parseInt(req.params.id as string);

    if (isNaN(projectId)) {
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
taskRouter.post("/sync_projects", auth, async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.user!;
    const projectsList = req.body; // โครงการที่ยังไม่ได้ sync (array)

    const syncedProjects = [];

    for (const p of projectsList) {
      const result = await db.transaction(async (tx) => {

        // Insert ตาราง projects
        const [newProject] = await tx
          .insert(projects)
          .values({
            name_project_id:    p.name_project_id,
            project_name:       p.project_name,
            project_details:    p.project_details,
            province:           p.province,
            sensor:             p.sensor,
            gsd_num:            p.gsd_num,
            gsd_unit:           p.gsd_unit,
            survey_main:        p.survey_main,
            survey_sub:         p.survey_sub,
            project_start_date: p.project_start_date,
            project_end_date:   p.project_end_date,
            project_note:       p.project_note,
          } satisfies Partial<NewProject>)
          .returning();

        if (!newProject) throw new Error("sync โครงการไม่สำเร็จ");

        // Insert ตาราง project_history
        await tx.insert(projectHistory).values({
          project_id:           newProject.id,
          project_user_creator: userId,
          project_time_created: sql`now()`,
        });

        // Insert ตาราง project_members (ถ้ามีสมาชิกในโครงการ)
        const memberIds = Array.isArray(p.member_ids) ? p.member_ids : [];
        if (memberIds.length > 0) {
          await tx.insert(projectMembers).values(
            memberIds.map((uid: number) => ({
              project_id:   newProject.id,
              user_id:      uid,
              time_add_members: sql`now()`,
            }))
          );
        }

        return newProject;
      });

      syncedProjects.push(result);
    }

    res.status(201).json(syncedProjects);
  } catch (e) {
    console.error("[POST /sync_projects] error:", e);
    res.status(500).json({ error: "sync โครงการไม่สำเร็จ" });
  }
});


export default taskRouter;