import { Router } from "express";
import { auth, type AuthRequest } from "../middleware/auth.js";
import { points, pointHistory, pointDataJson, users, projectMembers, projectHistory } from "../db/schema.js";
import { db } from "../db/index.js";
//import { sql } from "drizzle-orm";
import { sql, eq, asc, and, getTableColumns } from "drizzle-orm";
import { emptyToNull, toNumericOrNull, toIntOrNull } from "../helper/null.js";
import type { Response } from "express";
import multer from "multer";
import path from "path";
import fs from "fs";
import { fileTypeFromFile } from "file-type";


const point_task_Router = Router();


/// ─── ตรวจสอบว่า user นี้มีสิทธิ์แก้ไขโครงการนี้หรือไม่ ────────────────────────────────────
async function canEditProject(userId: number, projectId: number): Promise<boolean> {
  const [creatorRow] = await db
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

  const creatorId = creatorRow?.project_user_creator ?? null;
  if (creatorId === null) return false; // ไม่พบโครงการ

  const [currentUser] = await db
    .select({ id: users.id, status: users.status })
    .from(users)
    .where(eq(users.id, userId));

  if (currentUser?.status === "admin" && creatorId === userId) return true;

  const [member] = await db
    .select({ id: projectMembers.id })
    .from(projectMembers)
    .where(
      and(
        eq(projectMembers.project_id, projectId),
        eq(projectMembers.user_id, userId)
      )
    );

  return !!member;
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
const ALLOWED_MIME_TYPES = ["image/jpeg", "image/png", "image/webp", "image/heic", "image/heif", "application/octet-stream"];
const ALLOWED_EXTENSIONS = [".jpg", ".jpeg", ".png", ".webp", ".heic", ".heif"];
const ALLOWED_REAL_IMAGE_EXTS = ["jpg", "jpeg", "png", "webp", "heic", "heif"];

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
    cb(new Error("อนุญาตเฉพาะไฟล์ประเภทรูปภาพเท่านั้น (jpg, jpeg, png, webp, heic, heif)"));
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

/// จำกัดขนาดไฟล์สูงสุด 20MB ต่อไฟล์
const MAX_IMAGE_SIZE = 20 * 1024 * 1024;

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
    fileSize: MAX_IMAGE_SIZE,     // ขนาดไฟล์รูปสูงสุด 20MB ต่อไฟล์
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
        return res.status(400).json({ error: "ไฟล์รูปภาพห้ามมีขนาดเกิน 20MB" });
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




/* ============================================================
   ส่วนจัดการข้อมูล point
============================================================ */

/// ── สร้าง Point ใหม่ ──────────────────────────────────────────
point_task_Router.post("/create_point",
  auth,
  handleUploadFields,
  verifyUploadedImages,
  async (req: AuthRequest, res: Response) => {

    const files = req.files as
      | { [fieldname: string]: Express.Multer.File[] }
      | undefined;

    // รวม path ไฟล์รูปใน temp ทั้งหมด >> เพื่อลบทิ้งถ้า error
    const tempPaths = IMAGE_FIELDS
      .map((f) => files?.[f]?.[0]?.path)
      .filter(Boolean) as string[];

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
      } = req.body;


      const projectId = parseInt(project_id);
      if (isNaN(projectId)) {
        for (const p of tempPaths) if (fs.existsSync(p)) fs.unlinkSync(p);
        return res.status(400).json({ error: "project ID ไม่ถูกต้อง" });
      }

      // ตรวจสอบสิทธิ์ก่อนสร้าง point
      const hasAccess = await canEditProject(userId, projectId);
      if (!hasAccess) {
        for (const p of tempPaths) if (fs.existsSync(p)) fs.unlinkSync(p);
        return res.status(403).json({ error: "ไม่มีสิทธิ์เพิ่มข้อมูลในโครงการนี้" });
      }

      const result = await db.transaction(async (tx) => {

        // ── 1. Insert points (ยังไม่มีชื่อรูป) ───────────────
        const [newPoint] = await tx
          .insert(points)
          .values({
            project_id:    parseInt(project_id),
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
            
          })
          .returning();

        if (!newPoint) throw new Error("สร้างหมุดรังวัดไม่สำเร็จ");

        const projectId  = parseInt(project_id);
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
        const [updatedPoint] = await tx
          .select({
            ...getTableColumns(points),
            draw_data_json:    pointDataJson.draw_data_json,
            details_data_json: pointDataJson.details_data_json,
          })
          .from(points)
          .leftJoin(pointDataJson, eq(pointDataJson.point_id, points.id))
          .where(eq(points.id, pointId));

        return updatedPoint;
        
      });

      res.status(201).json(result);

    } catch (e) {
      console.error("[POST /create_point] error:", e);
      for (const p of tempPaths) {
        if (fs.existsSync(p)) fs.unlinkSync(p);
      }
      res.status(500).json({ error: "สร้างหมุดรังวัดไม่สำเร็จ" });
    }
  }
);


/// ── ดึง Point ทั้งหมดของโครงการ ──────────────────────────────
point_task_Router.get("/points/:project_id",
  auth,
  async (req: AuthRequest, res: Response) => {
    try {
      const projectId = parseInt(req.params["project_id"] as string);

      if (isNaN(projectId)) {
        res.status(400).json({ error: "Project ID ไม่ถูกต้อง" });
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
  async (req: AuthRequest, res: Response) => {

    const files = req.files as
      | { [fieldname: string]: Express.Multer.File[] }
      | undefined;

    const tempPaths = IMAGE_FIELDS
      .map((f) => files?.[f]?.[0]?.path)
      .filter(Boolean) as string[];

    try {
      const userId  = req.user!;
      const pointId = parseInt(req.params["point_id"] as string);

      if (isNaN(pointId)) {
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
      const hasAccess = await canEditProject(userId, projectId);
      if (!hasAccess) {
        for (const p of tempPaths) if (fs.existsSync(p)) fs.unlinkSync(p);
        return res.status(403).json({ error: "ไม่มีสิทธิ์แก้ไขข้อมูลในโครงการนี้" });
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
      const pointId = parseInt(req.params["point_id"] as string);

      if (isNaN(pointId)) {
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
        return res.status(403).json({ error: "ไม่มีสิทธิ์ลบข้อมูลในโครงการนี้" });
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



export default point_task_Router;


