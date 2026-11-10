import { Router } from "express";
import { auth, type AuthRequest } from "../middleware/auth.js";
import { points, pointHistory, pointDataJson, users, projectMembers, projectHistory } from "../db/schema.js";
import { db } from "../db/index.js";
//import { sql } from "drizzle-orm";
import { sql, eq, asc, and, getTableColumns } from "drizzle-orm";
import { emptyToNull, toNumericOrNull, toIntOrNull, parseId } from "../helper/null.js";
import type { Response } from "express";
import multer from "multer";
import path from "path";
import fs from "fs";
import { fileTypeFromFile } from "file-type";
import { normalizeUploadedFiles, ImageProcessError, POINT_IMAGE_OPTIONS } from "../helper/image.js";
import { getProjectAccess, canEditProject, canViewProject, activeGroupUserIds } from "../helper/project_access.js";


const point_task_Router = Router();


/// ─── ตรวจสอบผู้รังวัด / ผู้ตรวจสอบ ────────────────────────────────────
type SurveyPeople = { technician: number | null; qc: number | null };

async function assertSurveyPeople(creatorId: number, next: SurveyPeople, before?: SurveyPeople) {
  const check: number[] = [];
  if (next.technician !== null && next.technician !== before?.technician) check.push(next.technician);
  if (next.qc !== null && next.qc !== before?.qc) check.push(next.qc);
  if (check.length === 0) return;

  const active = await activeGroupUserIds(creatorId, check);
  if (check.some((id) => !active.has(id))) {
    throw new BadInput("ผู้รังวัดหรือผู้ตรวจสอบต้องเป็นสมาชิกในโครงการ");
  }
}



/* ============================================================
   ส่วนจัดการข้อมูลรูปภาพ
============================================================ */

/// ── รายชื่อ field รูปภาพ + หมายเลขลำดับ ──────────────────────
// ลำดับกำหนดเลขนำหน้าชื่อไฟล์
const IMAGE_FIELDS = [
  "point_zoomin_img",    // 1
  "point_zoomout_img",   // 2
  "point_survey_img",    // 3
  "point_controller_img",// 4
  "n_survey_img",        // 5
  "s_survey_img",        // 6
  "e_survey_img",        // 7
  "w_survey_img",        // 8
  "draw_img",            // 9
  "details_img",         // 10
  "draw_description_img", // 11
] as const;

type ImageField = typeof IMAGE_FIELDS[number];

// map field + เลขลำดับ
const IMAGE_FIELD_INDEX: Record<ImageField, number> = Object.fromEntries(
  IMAGE_FIELDS.map((field, i) => [field, i + 1])
) as Record<ImageField, number>;

// ── สร้างโฟลเดอร์ temp >> เก็บรูปยังไม่รู้ point_id ─────────
const tempDir = "uploads/point/temp";
if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });

// ─── อนุญาตเฉพาะไฟล์ประเภทรูปภาพเท่านั้น (ตรวจทั้ง mimetype และนามสกุลไฟล์) ────
const ALLOWED_MIME_TYPES = ["image/jpeg", "image/png", "image/webp", "application/octet-stream"];
const ALLOWED_EXTENSIONS = [".jpg", ".jpeg", ".png", ".webp"];
const ALLOWED_REAL_IMAGE_EXTS = ["jpg", "png", "webp"];

const imageFileFilter = (
  req: any,
  file: Express.Multer.File,
  cb: multer.FileFilterCallback
) => {
  const ext = path.extname(file.originalname).toLowerCase();

  const isMimeOk = ALLOWED_MIME_TYPES.includes(file.mimetype);
  const isExtOk  = ALLOWED_EXTENSIONS.includes(ext);

  if (isMimeOk && isExtOk) {
    cb(null, true);
  } else {
    cb(new Error("อนุญาตเฉพาะไฟล์ประเภทรูปภาพเท่านั้น (jpg, jpeg, png, webp)"));
  }
};

// ─── ตรวจสอบรูปแบบไฟล์ภาพ ─────────────────
async function verifyRealImageFile(filePath: string): Promise<boolean> {
  try {
    const type = await fileTypeFromFile(filePath);
    // ไฟล์เพี้ยน >> ปฏิเสธ
    if (!type) return false;
    return ALLOWED_REAL_IMAGE_EXTS.includes(type.ext);
  } catch {
    // อ่านไฟล์ไม่ได้ (เสีย, ถูกลบไปแล้ว) >> ปฏิเสธ
    return false;
  }
}

// ลบไฟล์ทิ้ง (เผื่อไฟล์ไม่มีแล้ว)
function safeUnlink(filePath?: string) {
  if (filePath && fs.existsSync(filePath)) {
    fs.unlinkSync(filePath);
  }
}

/// จำกัดขนาดไฟล์สูงสุด 15MB ต่อไฟล์
const MAX_IMAGE_SIZE = 15 * 1024 * 1024;
const MAX_IMAGE_SIZE_MB = MAX_IMAGE_SIZE / 1024 / 1024;

// counter ป้องกัน timestamp ชนกัน (แก้ปัญหาชื่อไฟล์ซ้ำ)
let _fileCounter = 0;

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, tempDir),
  filename: (_req, file, cb) => {
    // timestamp + counter + fieldname → ไม่มีทางซ้ำ
    const uniqueSuffix = `${Date.now()}_${++_fileCounter}_${file.fieldname}`;
    cb(null, `temp_${uniqueSuffix}${path.extname(file.originalname)}`);
  },
});

const uploadFields = multer({
  storage,
  fileFilter: imageFileFilter,
  limits: {
    fileSize: MAX_IMAGE_SIZE,     // ขนาดไฟล์รูปสูงสุดต่อไฟล์
    fieldSize: 50 * 1024 * 1024,  // ขนาด text field สูงสุด 50MB
  },
}).fields(
  IMAGE_FIELDS.map((name) => ({ name, maxCount: 1 }))
);


// ─── จับ error จาก multer (เช่น ไฟล์ไม่ใช่รูป, ไฟล์ใหญ่เกิน) ──
function handleUploadFields(req: any, res: Response, next: any) {
  uploadFields(req, res, (err: any) => {
    if (err instanceof multer.MulterError) {
      if (err.code === "LIMIT_FILE_SIZE") {
        return res.status(400).json({ error: `ไฟล์รูปภาพห้ามมีขนาดเกิน ${MAX_IMAGE_SIZE_MB}MB` });
      }
      return res.status(400).json({ error: err.message });
    } else if (err) {
      return res.status(400).json({ error: err.message });
    }
    next();
  });
}

// ─── ตรวจสอบว่าทุกไฟล์ที่แนบมาเป็นไฟล์รูปภาพจริง ────
async function verifyUploadedImages(req: any, res: Response, next: any) {
  const files = req.files as { [fieldname: string]: Express.Multer.File[] } | undefined;

  const candidates = IMAGE_FIELDS
    .map((f) => files?.[f]?.[0])
    .filter(Boolean) as Express.Multer.File[];

  // ไม่มีไฟล์แนบมา >> ข้าม
  if (candidates.length === 0) return next();

  for (const file of candidates) {
    const isRealImage = await verifyRealImageFile(file.path);
    if (!isRealImage) {
      // ลบไฟล์ที่ผิดพลาดทั้งหมดที่ multer (ทั้งอันที่ผิดและอันที่ถูก)
      candidates.forEach((f) => safeUnlink(f.path));
      return res.status(400).json({
        error: `ไฟล์ "${file.fieldname}" ไม่ใช่ไฟล์ประเภทรูปภาพ`,
      });
    }
  }
  next();
}

// ─── ประมวลผลรูปภาพทุกไฟล์ (ตัดข้อมูลแปลกปลอมในไฟล์) ────
async function normalizeImages(req: any, res: Response, next: any) {
  const files = req.files as { [fieldname: string]: Express.Multer.File[] } | undefined;

  const candidates = IMAGE_FIELDS
    .map((f) => files?.[f]?.[0])
    .filter(Boolean) as Express.Multer.File[];

  if (candidates.length === 0) return next();

  try {
    await normalizeUploadedFiles(candidates, () => POINT_IMAGE_OPTIONS);
    next();
  } catch (e) {
    candidates.forEach((f) => safeUnlink(f.path));
    if (e instanceof ImageProcessError) {
      return res.status(400).json({ error: e.message });
    }
    console.error("[normalizeImages] error:", e);
    return res.status(500).json({ error: "ประมวลผลรูปภาพไม่สำเร็จ" });
  }
}




/* ============================================================
   Idempotency (client_uuid)
============================================================ */

/// error ที่เกิดจากข้อมูลที่ client ส่งมา (ตอบ 400 ไม่ใช่ 500)
class BadInput extends Error {}

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

/// ── ดึง point พร้อม draw/details json ──
async function selectPointFull(executor: any, pointId: number) {
  const [row] = await executor
    .select({
      ...getTableColumns(points),
      draw_data_json:    pointDataJson.draw_data_json,
      details_data_json: pointDataJson.details_data_json,
    })
    .from(points)
    .leftJoin(pointDataJson, eq(pointDataJson.point_id, points.id))
    .where(eq(points.id, pointId));
  return row;
}

/// ── หา point ที่สร้างไปแล้วด้วย client_uuid เดียวกัน ─────────────
async function findPointByClientUuid(clientUuid: string, userId: number, projectId: number) {
  const [row] = await db
    .select({
      id:         points.id,
      project_id: points.project_id,
      creator:    pointHistory.point_user_creator,
    })
    .from(points)
    .leftJoin(pointHistory, and(
      eq(pointHistory.point_id, points.id),
      sql`${pointHistory.point_user_creator} IS NOT NULL`,
    ))
    .where(eq(points.client_uuid, clientUuid))
    .limit(1);

  if (!row) return null;
  if (row.project_id !== projectId || row.creator !== userId) return "mismatch" as const; // "mismatch" ถ้า uuid นี้เป็นของ user อื่นหรือโครงการอื่น
  return await selectPointFull(db, row.id);
}


/* ============================================================
   ส่วนจัดการข้อมูล point
============================================================ */

/// ── สร้าง Point ใหม่ ──────────────────────────────────────────
point_task_Router.post("/create_point",
  auth,
  handleUploadFields,
  verifyUploadedImages,
  normalizeImages,
  async (req: AuthRequest, res: Response) => {

    const files = req.files as
      | { [fieldname: string]: Express.Multer.File[] }
      | undefined;

    // รวม path ไฟล์รูปใน temp ทั้งหมด >> เพื่อลบทิ้งถ้า error หรือเป็นหมุดซ้ำ
    const tempPaths = IMAGE_FIELDS
      .map((f) => files?.[f]?.[0]?.path)
      .filter(Boolean) as string[];
    const cleanupTemp = () => tempPaths.forEach((p) => safeUnlink(p));

    try {
      const userId = req.user!;

      const {
        project_id,
        point_name,
        northing,
        easting,
        height_m,
        ellipsoidal_m,
        antenna_m,
        datum,
        utm,
        egm,
        survey_main,
        survey_sub,
        gdop_m,
        pdop_m,
        hdop_m,
        dcq_m,
        tambon,
        amphoe,
        province,
        point_date,
        job,
        gnss,
        rf_1,
        distance_m_1,
        az_1,
        rf_2,
        distance_m_2,
        az_2,
        survey_technician,
        survey_qc,
        point_note,

        draw_data_json,
        details_data_json,
        client_uuid,
      } = req.body;


      const projectId = parseId(project_id);
      if (projectId === null) {
        cleanupTemp();
        return res.status(400).json({ error: "project ID ไม่ถูกต้อง" });
      }

      // ตรวจสอบสิทธิ์ก่อนสร้าง point
      const access = await getProjectAccess(userId, projectId);
      if (!access?.canEdit) {
        cleanupTemp();
        return res.status(403).json({ error: "คุณไม่มีสิทธิ์เพิ่มข้อมูลในโครงการนี้" });
      }

      // ── ตรวจและแปลงข้อมูลก่อนเปิด transaction >> ข้อมูลผิดตอบ 400 (client จะไม่ retry ซ้ำ) ──
      let clientUuid: string | null;
      let values: Record<string, any>;
      try {
        clientUuid = parseClientUuid(client_uuid);

        const pointName = typeof point_name === "string" ? point_name.trim() : "";
        if (!pointName || pointName.length > 500) throw new BadInput("ชื่อหมุดรังวัดไม่ถูกต้อง");

        values = {
          project_id:    projectId,
          point_name:    pointName,

          northing:      toNumericOrNull(northing, "Northing"),
          easting:       toNumericOrNull(easting, "Easting"),
          height_m:      toNumericOrNull(height_m, "Ortho Height"),
          ellipsoidal_m: toNumericOrNull(ellipsoidal_m, "ความสูงเหนือทรงรี"),
          antenna_m:     toNumericOrNull(antenna_m, "Antenna Height"),
          datum:         emptyToNull(datum),
          utm:           emptyToNull(utm),
          egm:           emptyToNull(egm),

          survey_main:   emptyToNull(survey_main),
          survey_sub:    emptyToNull(survey_sub),

          gdop_m:        toNumericOrNull(gdop_m, "GDOP"),
          pdop_m:        toNumericOrNull(pdop_m, "PDOP"),
          hdop_m:        toNumericOrNull(hdop_m, "HDOP"),
          dcq_m:         toNumericOrNull(dcq_m, "3DCQ"),

          tambon:        emptyToNull(tambon),
          amphoe:        emptyToNull(amphoe),
          province:      emptyToNull(province),
          point_date:    emptyToNull(point_date),

          job:           emptyToNull(job),
          gnss:          emptyToNull(gnss),
          rf_1:          emptyToNull(rf_1),
          distance_m_1:  toNumericOrNull(distance_m_1, "ระยะ RF1"),
          az_1:          toIntOrNull(az_1, "AZ1"),
          rf_2:          emptyToNull(rf_2),
          distance_m_2:  toNumericOrNull(distance_m_2, "ระยะ RF2"),
          az_2:          toIntOrNull(az_2, "AZ2"),

          survey_technician: toIntOrNull(survey_technician, "ผู้รังวัด"),
          survey_qc:         toIntOrNull(survey_qc, "ผู้ตรวจสอบ"),

          point_note:    emptyToNull(point_note),

          client_uuid:   clientUuid,
        };

        // หมุดใหม่: ผู้รังวัด/ผู้ตรวจสอบต้องยังอยู่ในกลุ่ม
        await assertSurveyPeople(access.creatorId, {
          technician: values.survey_technician,
          qc:         values.survey_qc,
        });
      } catch (e) {
        cleanupTemp();
        return res.status(400).json({ error: (e as Error).message });
      }

      // ── เคยสร้างด้วย client_uuid นี้แล้ว >> คืนหมุดเดิม ไม่สร้างซ้ำ ──
      if (clientUuid) {
        const existing = await findPointByClientUuid(clientUuid, userId, projectId);
        if (existing === "mismatch") {
          cleanupTemp();
          return res.status(409).json({ error: "client_uuid ซ้ำกับข้อมูลอื่น" });
        }
        if (existing) {
          cleanupTemp();
          return res.status(201).json(existing);
        }
      }

      const result = await db.transaction(async (tx) => {

        // ── 1. Insert points (ยังไม่มีชื่อรูป) ───────────────
        const [newPoint] = await tx
          .insert(points)
          .values(values as any)
          .returning();

        if (!newPoint) throw new Error("สร้างหมุดรังวัดไม่สำเร็จ");

        const pointId = newPoint.id;
        const time   = Date.now();

        // ── 2. สร้างโฟเดอร์ uploads/point/{project_id}/{point_id} ──
        const pointDir = `uploads/point/${projectId}/${pointId}`;
        if (!fs.existsSync(pointDir)) {
          fs.mkdirSync(pointDir, { recursive: true });
        }

        // ── 3. copy temp เป็น ชื่อจริง (รูปแบบชื่อ: {projectID}_{pointID}_{เลขลำดับ}_{fieldname}_{ts}.jpg) ───────────────────────────
        const imageUpdates: Partial<Record<ImageField, string>> = {};

        for (const field of IMAGE_FIELDS) {
          const file = files?.[field]?.[0];
          if (!file) continue;

          if (!fs.existsSync(file.path)) {
            console.warn(`[WARN] temp file not found: ${file.path}`);
            continue;
          }

          const ext         = path.extname(file.originalname) || ".jpg";
          const fieldNum    = IMAGE_FIELD_INDEX[field]; // เลขลำดับ
          const newFileName = `${projectId}_${pointId}_${fieldNum}_${field}_${time}${ext}`;
          const newPath     = path.join(pointDir, newFileName);

          // copy + delete แทน rename (ป้องกัน cross-device error ใน Docker)
          fs.copyFileSync(file.path, newPath);
          fs.unlinkSync(file.path);

          imageUpdates[field] = newFileName;
        }

        // ── 4. Update ชื่อรูปลง DB ────────────────────────────
        if (Object.keys(imageUpdates).length > 0) {
          await tx
            .update(points)
            .set(imageUpdates)
            .where(eq(points.id, pointId));
        }

        // ── 5. Insert point_history ────────────────────────────
        await tx.insert(pointHistory).values({
          project_id:         projectId,
          point_id:           pointId,
          point_user_creator: userId,
          point_time_created: sql`now()`,
        });

        // ── 6. Insert point_data_json ─────────────────────
        await tx.insert(pointDataJson).values({
          point_id: pointId,
          draw_data_json:    emptyToNull(draw_data_json),
          details_data_json: emptyToNull(details_data_json),
        });

        // ── 7. ดึงข้อมูลล่าสุด ────────────────────────────────
        return await selectPointFull(tx, pointId);
      });

      res.status(201).json(result);

    } catch (e) {
      cleanupTemp();

      // request ซ้ำมาพร้อมกัน 2 ตัว >> คืนหมุดที่อีกตัวสร้างไว้
      if (isUniqueViolation(e) && req.body?.client_uuid) {
        try {
          const projectId = parseId(req.body.project_id);
          const existing = projectId === null ? null : await findPointByClientUuid(
            String(req.body.client_uuid).toLowerCase(), req.user!, projectId,
          );
          if (existing && existing !== "mismatch") return res.status(201).json(existing);
        } catch (_) {}
      }

      console.error("[POST /create_point] error:", e);
      res.status(500).json({ error: "สร้างหมุดรังวัดไม่สำเร็จ" });
    }
  }
);


/// ── ดึง Point ทั้งหมดของโครงการ ──────────────────────────────
point_task_Router.get("/points/:project_id",
  auth,
  async (req: AuthRequest, res: Response) => {
    try {
      const projectId = parseId(req.params["project_id"]);

      if (projectId === null) {
        res.status(400).json({ error: "Project ID ไม่ถูกต้อง" });
        return;
      }

      // ตรวจสอบสิทธิ์เข้าถึงข้อมูลโครงการนี้
      const hasAccess = await canViewProject(req.user!, projectId);
      if (!hasAccess) {
        res.status(403).json({ error: "คุณไม่มีสิทธิ์เข้าถึงข้อมูลในโครงการนี้" });
        return;
      }

      const allPoints = await db
      .select({
        ...getTableColumns(points),
        draw_data_json:    pointDataJson.draw_data_json,
        details_data_json: pointDataJson.details_data_json,
      })
      .from(points)
      .leftJoin(pointDataJson, eq(pointDataJson.point_id, points.id))
      .where(eq(points.project_id, projectId))
      .orderBy(asc(points.point_name));

      res.status(200).json(allPoints);
    } catch (e) {
      console.error("[GET /points/:project_id] error:", e);
      res.status(500).json({ error: "ดึงข้อมูลหมุดรังวัดไม่สำเร็จ" });
    }
  }
);


/// ── อัปเดทข้อมูล Point ──────────────────────────────────────────────
point_task_Router.put("/update_point/:point_id",
  auth,
  handleUploadFields,
  verifyUploadedImages,
  normalizeImages,
  async (req: AuthRequest, res: Response) => {

    const files = req.files as
      | { [fieldname: string]: Express.Multer.File[] }
      | undefined;

    const tempPaths = IMAGE_FIELDS
      .map((f) => files?.[f]?.[0]?.path)
      .filter(Boolean) as string[];

    try {
      const userId  = req.user!;
      const pointId = parseId(req.params["point_id"]);

      if (pointId === null) {
        res.status(400).json({ error: "point ID ไม่ถูกต้อง" });
        return;
      }

      // ── ดึงข้อมูล point เดิม ──────────────────────────────────────
      const [existing] = await db
        .select()
        .from(points)
        .where(eq(points.id, pointId));

      if (!existing) {
        res.status(404).json({ error: "ไม่พบหมุดรังวัด" });
        return;
      }

      const projectId = existing.project_id;

      // ตรวจสอบสิทธิ์แก้ไข point ในโครงการนี้
      const access = await getProjectAccess(userId, projectId);
      if (!access?.canEdit) {
        for (const p of tempPaths) if (fs.existsSync(p)) fs.unlinkSync(p);
        return res.status(403).json({ error: "คุณไม่มีสิทธิ์แก้ไขข้อมูลในโครงการนี้" });
      }

      // ผู้รังวัด/ผู้ตรวจสอบ: ค่าที่เปลี่ยนใหม่ต้องอยู่ในกลุ่ม ค่าเดิมคงไว้ได้ (แม้ถูกถอนอนุมัติแล้ว)
      try {
        await assertSurveyPeople(
          access.creatorId,
          {
            technician: toIntOrNull(req.body.survey_technician, "ผู้รังวัด"),
            qc:         toIntOrNull(req.body.survey_qc, "ผู้ตรวจสอบ"),
          },
          { technician: existing.survey_technician, qc: existing.survey_qc }
        );
      } catch (e) {
        for (const p of tempPaths) if (fs.existsSync(p)) fs.unlinkSync(p);
        return res.status(400).json({ error: (e as Error).message });
      }

      const {
        point_name, 
        northing, 
        easting, 
        height_m, 
        ellipsoidal_m,
        antenna_m, 
        datum, 
        utm, 
        egm, 
        survey_main, 
        survey_sub,
        gdop_m, 
        pdop_m, 
        hdop_m, 
        dcq_m, 
        tambon, 
        amphoe, 
        province,
        point_date, 
        job, 
        gnss, 
        rf_1, 
        distance_m_1, 
        az_1,
        rf_2, 
        distance_m_2, 
        az_2, 
        survey_technician, 
        survey_qc,
        point_note,
        remove_images,

        draw_data_json,
        details_data_json,
      } = req.body;

      const removedFields: string[] = remove_images
        ? String(remove_images).split(",").map((s) => s.trim()).filter(Boolean)
        : [];

      const result = await db.transaction(async (tx) => {

        const updateValues: Record<string, any> = {

          point_name,

            northing:      toNumericOrNull(northing, "Northing"),
            easting:       toNumericOrNull(easting, "Easting"),
            height_m:      toNumericOrNull(height_m, "Ortho Height"),
            ellipsoidal_m: toNumericOrNull(ellipsoidal_m, "ความสูงเหนือทรงรี"),
            antenna_m:     toNumericOrNull(antenna_m, "Antenna Height"),
            datum:         emptyToNull(datum),
            utm:           emptyToNull(utm),
            egm:           emptyToNull(egm),

            survey_main:   emptyToNull(survey_main),
            survey_sub:    emptyToNull(survey_sub),

            gdop_m:        toNumericOrNull(gdop_m, "GDOP"),
            pdop_m:        toNumericOrNull(pdop_m, "PDOP"),
            hdop_m:        toNumericOrNull(hdop_m, "HDOP"),
            dcq_m:         toNumericOrNull(dcq_m, "3DCQ"),

            tambon:        emptyToNull(tambon),
            amphoe:        emptyToNull(amphoe),
            province:      emptyToNull(province),
            point_date:    emptyToNull(point_date),

            job:           emptyToNull(job),
            gnss:          emptyToNull(gnss),
            rf_1:          emptyToNull(rf_1),
            distance_m_1:  toNumericOrNull(distance_m_1, "ระยะ RF1"),
            az_1:          toIntOrNull(az_1, "AZ1"),
            rf_2:          emptyToNull(rf_2),
            distance_m_2:  toNumericOrNull(distance_m_2, "ระยะ RF2"),
            az_2:          toIntOrNull(az_2, "AZ2"),

            survey_technician: toIntOrNull(survey_technician, "ผู้รังวัด"),
            survey_qc:         toIntOrNull(survey_qc, "ผู้ตรวจสอบ"),

            point_note:    emptyToNull(point_note),
        };

        // ── Upsert point_data_json (เฉพาะเมื่อมีการส่งค่าเข้ามาจริง) ──
        const drawJsonVal    = emptyToNull(draw_data_json);
        const detailsJsonVal = emptyToNull(details_data_json);

        if (drawJsonVal !== undefined || detailsJsonVal !== undefined) {
          await tx.insert(pointDataJson)
            .values({
              point_id:          pointId,
              draw_data_json:    drawJsonVal ?? null,
              details_data_json: detailsJsonVal ?? null,
            })
            .onConflictDoUpdate({
              target: pointDataJson.point_id,
              set: {
                ...(drawJsonVal    !== undefined ? { draw_data_json: drawJsonVal } : {}),
                ...(detailsJsonVal !== undefined ? { details_data_json: detailsJsonVal } : {}),
              },
            });
        }

        // ── จัดการรูปภาพ ─────────────────────────────────────
        const pointDir = `uploads/point/${projectId}/${pointId}`;
        if (!fs.existsSync(pointDir)) {
          fs.mkdirSync(pointDir, { recursive: true });
        }

        const ts = Date.now();

        for (const field of IMAGE_FIELDS) {
          const file = files?.[field]?.[0];

          // ลบไฟล์ภาพ >> เคลียร์ field + ลบไฟล์เดิมออกจาก disk
          if (!file && removedFields.includes(field)) {
            const oldFileName = (existing as any)[field];
            if (oldFileName) {
              const oldPath = path.join(pointDir, oldFileName);
              if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
            }
            updateValues[field] = null;
            continue;
          }

          if (!file) continue;

          if (!fs.existsSync(file.path)) {
            console.warn(`[WARN] temp file not found: ${file.path}`);
            continue;
          }

          // ── ลบรูปเดิมถ้ามี ─────────────────────────────────
          const oldFileName = (existing as any)[field];
          if (oldFileName) {
            const oldPath = path.join(pointDir, oldFileName);
            if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
          }

          const ext      = path.extname(file.originalname) || ".jpg";
          const fieldNum = IMAGE_FIELD_INDEX[field];
          const newFileName = `${projectId}_${pointId}_${fieldNum}_${field}_${ts}${ext}`;
          const newPath  = path.join(pointDir, newFileName);

          fs.copyFileSync(file.path, newPath);
          fs.unlinkSync(file.path);

          updateValues[field] = newFileName;
        }

        // ── Update points ─────────────────────────────────────
        await tx
          .update(points)
          .set(updateValues)
          .where(eq(points.id, pointId));

        // ── Insert point_history ──────────────────────────────
        await tx.insert(pointHistory).values({
          project_id:         projectId,
          point_id:           pointId,
          point_user_updated: userId,
          point_time_updated: sql`now()`,
        });

        // ── ดึงข้อมูล draw_data_json / details_data_json ──────────────────────────────
        const [result] = await tx
          .select({
            ...getTableColumns(points),
            draw_data_json:    pointDataJson.draw_data_json,
            details_data_json: pointDataJson.details_data_json,
          })
          .from(points)
          .leftJoin(pointDataJson, eq(pointDataJson.point_id, points.id))
          .where(eq(points.id, pointId));

        return result;

      });

      res.status(200).json(result);

    } catch (e) {
      console.error("[PUT /update_point] error:", e);
      for (const p of tempPaths) {
        if (fs.existsSync(p)) fs.unlinkSync(p);
      }
      res.status(500).json({ error: "แก้ไขหมุดรังวัดไม่สำเร็จ" });
    }
  }
);


/// ── ลบ Point ──────────────────────────────────────────────────
point_task_Router.delete("/delete_point/:point_id",
  auth,
  async (req: AuthRequest, res: Response) => {
    try {
      const userId  = req.user!;
      const pointId = parseId(req.params["point_id"]);

      if (pointId === null) {
        res.status(400).json({ error: "point ID ไม่ถูกต้อง" });
        return;
      }

      // ── ดึงข้อมูล point ก่อน (เพื่อเอา project_id ไปลบโฟเดอร์) ──
      const [existingPoint] = await db
        .select({ id: points.id, project_id: points.project_id })
        .from(points)
        .where(eq(points.id, pointId));

      if (!existingPoint) {
        res.status(404).json({ error: "ไม่พบหมุดรังวัดที่ต้องการลบ" });
        return;
      }

      const projectId = existingPoint.project_id;

      // ตรวจสอบสิทธิ์ลบ point ในโครงการนี้
      const hasAccess = await canEditProject(userId, projectId);
      if (!hasAccess) {
        return res.status(403).json({ error: "คุณไม่มีสิทธิ์ลบข้อมูลในโครงการนี้" });
      }

      await db.transaction(async (tx) => {

        // ── 1. Insert point_history บันทึกการลบ ────────────────
        await tx.insert(pointHistory).values({
          project_id:        projectId,
          point_id:          pointId,
          point_user_delete: userId,
          point_time_delete: sql`now()`,
        });

        // ── 2. ลบ point ออกจาก DB ──────────────────────────────
        await tx
          .delete(points)
          .where(eq(points.id, pointId));

      });

      // ── 3. ลบโฟเดอร์รูปภาพทั้งหมดของ point ──────────────────
      const pointDir = path.join("uploads", "point", String(projectId), String(pointId));
      if (fs.existsSync(pointDir)) {
        fs.rmSync(pointDir, { recursive: true, force: true });
        console.log(`[DELETE] removed dir: ${pointDir}`);
      }

      res.status(200).json({ message: "ลบหมุดรังวัดสำเร็จ" });

    } catch (e) {
      console.error("[DELETE /delete_point] error:", e);
      res.status(500).json({ error: "ลบหมุดรังวัดไม่สำเร็จ" });
    }
  }
);



/* ============================================================
   ส่งไฟล์รูปของ Point (ต้อง login + มีสิทธิ์เข้าถึงโครงการ) 
============================================================ */
const POINT_UPLOAD_ROOT = path.resolve("uploads", "point");

point_task_Router.get("/image/:project_id/:point_id/:filename",
  auth,
  async (req: AuthRequest, res: Response) => {
    try {
      const projectId = parseId(req.params["project_id"]);
      const pointId   = parseId(req.params["point_id"]);
      const filename  = String(req.params["filename"] ?? "");

      // id ผิดรูปแบบ (เช่น id ติดลบของหมุด offline) >> ไม่มีรูปนี้บน server
      if (projectId === null || pointId === null || !filename) {
        res.status(404).json({ error: "ไม่พบรูปภาพ" });
        return;
      }

      // ตรวจสิทธิ์
      const hasAccess = await canViewProject(req.user!, projectId);
      if (!hasAccess) {
        res.status(403).json({ error: "คุณไม่มีสิทธิ์เข้าถึงข้อมูลโครงการ" });
        return;
      }

      const [p] = await db
        .select()
        .from(points)
        .where(and(eq(points.id, pointId), eq(points.project_id, projectId)));

      // ชื่อไฟล์ต้องตรงกับที่บันทึกไว้ใน DB
      const isOwnFile =
        !!p &&
        path.basename(filename) === filename &&
        IMAGE_FIELDS.some((f) => p[f] === filename);

      if (!isOwnFile) {
        res.status(404).json({ error: "ไม่พบรูปภาพ" });
        return;
      }

      const filePath = path.join(POINT_UPLOAD_ROOT, String(projectId), String(pointId), filename);

      res.set("Cache-Control", "private, max-age=300");
      res.set("X-Content-Type-Options", "nosniff");
      res.sendFile(filePath, { dotfiles: "deny" }, (err) => {
        if (err && !res.headersSent) {
          res.status(404).json({ error: "ไม่พบรูปภาพ" });
        }
      });
    } catch (e) {
      console.error("[GET /image] error:", e);
      if (!res.headersSent) res.status(500).json({ error: "ดึงรูปภาพไม่สำเร็จ" });
    }
  }
);



export default point_task_Router;