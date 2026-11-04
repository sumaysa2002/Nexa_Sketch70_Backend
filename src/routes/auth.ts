import type { Request, Response } from "express"; // เพื่อให้ TypeScript เช็คชนิดข้อมูล
import { Router } from "express";
import { db } from "../db/index.js"; // ตัวเชื่อม Drizzle  ↔ PostgreSQL
import { users, usersHistory } from "../db/schema.js";
import { eq, ne, and, or, sql, asc, inArray, isNull } from "drizzle-orm"; // ฟังก์ชันช่วยเขียน WHERE email = ?   เพิ่ม sql 
import bcryptjs from "bcryptjs"; // ใช้ hash password
import jwt from "jsonwebtoken";
import { auth, requireAdmin, type AuthRequest } from "../middleware/auth.js"; // ใช้ตรวจสอบ JWT token ก่อนเข้าถึง route ที่ต้อง login
import {
  sendOTP,
  verifyOTP,
  isKnownChallenge,
  otpFailureMessage,
  OtpError,
  type OtpVerifyResult,
} from "../services/otp.service.js";
import crypto from "crypto";
import { emptyToNull, toNumericOrNull, toIntOrNull } from "../helper/null.js";
import { parseEmail, userEmailEquals } from "../helper/email.js";
import multer from "multer";
import path from "path";
import fs from "fs";
import { fileTypeFromFile } from "file-type";
import {
  normalizeUploadedFiles,
  ImageProcessError,
  PROFILE_IMAGE_OPTIONS,
  SIGNATURE_IMAGE_OPTIONS,
} from "../helper/image.js";


const authRouter = Router();

/// ─── ตัด password ออกจาก user object ก่อนส่งกลับ client ──────────
function sanitizeUser<T extends { password?: unknown }>(u: T): Omit<T, "password"> {
  const { password, ...safeUser } = u;
  return safeUser;
}

/// ─── error ค่าซ้ำจาก PostgreSQL (unique violation) ──────────
const isUniqueViolation = (e: any): boolean => e?.code === "23505" || e?.cause?.code === "23505";

/// ─── ตัวช่วยฝั่ง OTP / validation ──────────
const MIN_PASSWORD_LENGTH = 6; // ให้ตรงกับ Flutter
const isNonEmptyString = (v: unknown): v is string => typeof v === "string" && v.trim().length > 0;

// hash จำลองไว้ใช้ตอน bcrypt.compare กรณีไม่พบ user → ใช้เวลาเท่ากัน เดาไม่ได้ว่าอีเมลมีในระบบหรือไม่
const DUMMY_PASSWORD_HASH = bcryptjs.hashSync(crypto.randomBytes(16).toString("hex"), 10);

// แปลง error จาก OTP service เป็น response (errorKey = ชื่อฟิลด์ที่ Flutter อ่าน: "message" หรือ "error")
function sendOtpError(
  res: Response,
  e: unknown,
  fallback: string,
  errorKey: "message" | "error" = "message"
) {
  if (e instanceof OtpError) {
    if (e.retryAfterSeconds) res.set("Retry-After", String(e.retryAfterSeconds));
    return res.status(e.status).json({
      [errorKey]: e.message,
      ...(e.retryAfterSeconds ? { retry_after_seconds: e.retryAfterSeconds } : {}),
    });
  }
  console.error("[OTP] error:", e);
  return res.status(500).json({ [errorKey]: fallback });
}

// ตอบกลับเมื่อยืนยัน OTP ไม่ผ่าน → แนบจำนวนครั้งที่กรอกไปแล้ว ให้หน้า OTP แสดงได้
function sendOtpVerifyFail(res: Response, r: OtpVerifyResult) {
  return res.status(400).json({
    message: otpFailureMessage(r),
    reason: r.reason,
    attempts: r.attempts,
    max_attempts: r.maxAttempts,
    remaining_attempts: r.remaining,
    ref_code: r.refCode,
  });
}


/* ============================================================
   ส่วนจัดการข้อมูลรูปภาพ
============================================================ */

/// ─── สร้างโฟลเดอร์เก็บรูป profiles (ถ้ายังไม่มีก็สร้างให้อัตโนมัติ) ──────────────────────────────────────
const uploadDir = 'uploads/profiles';
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

/// ─── สร้างโฟลเดอร์เก็บรูป signatures (ถ้ายังไม่มีก็สร้างให้อัตโนมัติ) ────────────────────────────────────
const signatureDir = 'uploads/signatures';
if (!fs.existsSync(signatureDir)) {
  fs.mkdirSync(signatureDir, { recursive: true });
}

/// ─── ตั้งชื่อไฟล์ชั่วคราว ────────────────────────────────────
// counter ป้องกัน filename ชนกัน
let _authFileCounter = 0;
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        // ชื่อไฟล์ชั่วคราวแบบสุ่มทั้งหมด (ห้ามใช้ข้อมูลจาก client เช่น email → เสี่ยง path traversal)
        const ext = path.extname(file.originalname).toLowerCase();
        const uniqueSuffix = `${Date.now()}_${++_authFileCounter}_${crypto.randomBytes(8).toString("hex")}`;
        cb(null, `tmp_${file.fieldname}_${uniqueSuffix}${ext}`);
    }
});

// ─── อนุญาตเฉพาะไฟล์ประเภทรูปภาพเท่านั้น (ตรวจทั้ง mimetype และนามสกุลไฟล์) ────
const ALLOWED_MIME_TYPES = ["image/jpeg", "image/png", "image/webp"];
const ALLOWED_EXTENSIONS = [".jpg", ".jpeg", ".png", ".webp"];
const ALLOWED_REAL_IMAGE_EXTS = ["jpg", "png", "webp"];

const imageFileFilter = (
  req: Request,
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

// ─── ตรวจสอบรูปแบบไฟล์ภาพ ────────────────────────────────────
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

/// จำกัดขนาดไฟล์สูงสุด 5MB ต่อไฟล์
const MAX_IMAGE_SIZE = 5 * 1024 * 1024;
const MAX_IMAGE_SIZE_MB = MAX_IMAGE_SIZE / 1024 / 1024;

// ─── ประมวลผลรูปภาพทุกไฟล์ (ตัดข้อมูลแปลกปลอมในไฟล์) ────
async function normalizeUserImages(files: Express.Multer.File[]): Promise<string | null> {
  try {
    await normalizeUploadedFiles(files, (f) =>
      f.fieldname === "signature_image" ? SIGNATURE_IMAGE_OPTIONS : PROFILE_IMAGE_OPTIONS
    );
    return null;
  } catch (e) {
    files.forEach((f) => safeUnlink(f.path));
    if (e instanceof ImageProcessError) return e.message;
    console.error("[normalizeUserImages] error:", e);
    return "ประมวลผลรูปภาพไม่สำเร็จ";
  }
}

/// ใช้ตอนสมัครสมาชิก (มีแค่ profile_image)
const upload = multer({ 
  storage,
  fileFilter: imageFileFilter,
  limits: { fileSize: MAX_IMAGE_SIZE },
});

/// ใช้ตอน update profile (profile_image + signature_image)
const uploadFields = multer({ 
  storage,
  fileFilter: imageFileFilter,
  limits: { fileSize: MAX_IMAGE_SIZE },
}).fields([
  { name: 'profile_image', maxCount: 1 },
  { name: 'signature_image', maxCount: 1 },
]);



/* ============================================================
   1) SIGNUP
============================================================ */

/// ── เช็ค Email ซ้ำในระบบ ──────────────────────────────────────
authRouter.post("/signup/check_email", async (req: Request, res: Response) => {
  try {
    const email = parseEmail(req.body.email);

    if (!email) {
      return res.status(400).json({
        message: "รูปแบบอีเมลไม่ถูกต้อง",
      });
    }

    const existingUser = await db
      .select({ id: users.id })
      .from(users)
      .where(userEmailEquals(email));

    // มี email แล้ว
    if (existingUser.length > 0) {
      return res.status(200).json({
        exists: true,
      });
    }

    // ยังไม่มี
    return res.status(200).json({
      exists: false,
    });
  } catch (e) {
    res.status(500).json({
      message: "ตรวจสอบอีเมลไม่สำเร็จ",
    });
  }
});


/// ── ส่งรหัส OTP ไปยัง email ──────────────────────────────────────
authRouter.post("/signup/send_otp", async (req: Request, res: Response) => {
  try {
    const email = parseEmail(req.body.email);
    if (!email) return res.status(400).json({ message: "รูปแบบอีเมลไม่ถูกต้อง" });

    // อีเมลที่สมัครแล้ว ไม่ต้องส่ง OTP สมัครสมาชิก
    const [existing] = await db.select({ id: users.id }).from(users).where(userEmailEquals(email));
    if (existing) return res.status(409).json({ message: "อีเมลนี้อยู่ในระบบแล้ว" });

    const { hash, refCode } = await sendOTP({ email, purpose: "signup" });
    res.status(200).json({ success: true, hash, ref_code: refCode });
  } catch (error) {
    return sendOtpError(res, error, "ส่ง OTP ไม่สำเร็จ");
  }
});


/// ── ตรวจสอบ OTP และ insert user เข้าฐานข้อมูล ──────────────────────────────────────
authRouter.post("/signup/verify_and_register",
  (req: Request, res: Response, next) => {
    upload.single('profile_image')(req, res, (err: any) => {
      if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
          return res.status(400).json({ message: `ไฟล์รูปภาพห้ามมีขนาดเกิน ${MAX_IMAGE_SIZE_MB}MB` });
        }
        return res.status(400).json({ message: err.message });
      } else if (err) {
        return res.status(400).json({ message: err.message });
      }
      next();
    });
  },
  async (req: Request, res: Response, next) => {

    // ไม่มีไฟล์แนบมา >> ข้าม
    if (!req.file) return next();
 
    const isRealImage = await verifyRealImageFile(req.file.path);
    if (!isRealImage) {
      safeUnlink(req.file.path);
      return res.status(400).json({
        message: "ไฟล์ที่แนบมาไม่ใช่ไฟล์ประเภทรูปภาพ",
      });
    }

    const imageError = await normalizeUserImages([req.file]);
    if (imageError) return res.status(400).json({ message: imageError });

    next();
  },
  async (req: Request, res: Response) => {
    try {

        // แปลงข้อมูล payload จาก JSON String เป็น Object ที่ JavaScript/TypeScript สามารถใช้งานได้
        const payload = JSON.parse(req.body.payload);

        // ดึง OTP และ hash
        const { otp, hash } = req.body;

        // อีเมลรูปแบบมาตรฐาน (ตัวพิมพ์เล็ก ไม่มีช่องว่าง)
        const email = parseEmail(payload?.email);

        // ตรวจข้อมูลจำเป็นก่อน (ยังไม่ใช้ OTP ถ้าข้อมูลไม่ครบ)
        if (
          !payload || !email ||
          typeof payload.password !== "string" || payload.password.length < MIN_PASSWORD_LENGTH
        ) {
            safeUnlink(req.file?.path);
            return res.status(400).json({ message: "ข้อมูลไม่ครบถ้วนหรือรหัสผ่านสั้นเกินไป" });
        }

        // ตรวจสอบ OTP (ต้อง await และต้องเป็น OTP ของการสมัครสมาชิกเท่านั้น)
        const otpResult = await verifyOTP({ email, otp, hash, purpose: "signup" });
        if (!otpResult.ok) {
            safeUnlink(req.file?.path);
            return sendOtpVerifyFail(res, otpResult);
        }

        // Hash Password
        const hashedPassword = await bcryptjs.hash(payload.password, 10);

        // เตรียมชื่อไฟล์ profile
        const profileImageName = req.file ? req.file.filename : null;

        // Insert เข้าฐานข้อมูล
        const result = await db.transaction(async (tx) => {
            const insertedUsers = await tx.insert(users).values({
                title_name: payload.title_name,
                first_name: payload.first_name,
                last_name: payload.last_name,
                phone: payload.phone,
                email,
                password: hashedPassword,

                job_position:   emptyToNull(payload.job_position),
                job_level:      emptyToNull(payload.job_level),
                job_office:     emptyToNull(payload.job_office),
                job_department: emptyToNull(payload.job_department),

                profile_img: profileImageName,
            }).returning();

            // ดึง User ที่เพิ่งสร้าง
            const newUser = insertedUsers[0]!;
            
            // ถ้ามีรูป profile → เปลี่ยนชื่อไฟล์
            if (req.file) {
                const ext = path.extname(req.file.originalname);
                const timestamp = Date.now();
                const newFileName = `${newUser.id}_profile_img_${timestamp}${ext}`;

                // ย้ายไฟล์ไปยังชื่อใหม่
                const oldPath = req.file.path;
                const newPath = path.join(uploadDir, newFileName);
                fs.renameSync(oldPath, newPath);
                
                // Update ชื่อรูปใน Database
                await tx.update(users)
                    .set({ profile_img: newFileName })
                    .where(eq(users.id, newUser.id));
            }

            // บันทึกประวัติ User
            await tx.insert(usersHistory).values({
                user_id: newUser.id,
                user_create: newUser.id,
                time_user_create: sql`now()`,
            });
            
            return newUser;
        });

        res.status(201).json({ message: "สมัครสมาชิกสำเร็จ", user_id: result.id });
    } catch (error) {
        safeUnlink(req.file?.path);
        // อีเมลซ้ำ (เช่น สมัครพร้อมกัน 2 request หรือต่างกันแค่ตัวพิมพ์เล็ก/ใหญ่)
        if (isUniqueViolation(error)) {
            return res.status(409).json({ message: "อีเมลนี้อยู่ในระบบแล้ว" });
        }
        console.error(error);
        res.status(500).json({ message: "สมัครสมาชิกไม่สำเร็จ" });
    }
});



/* ============================================================
   2) LOGIN
============================================================ */

/// ── เช็ค email + password >> ส่ง OTP ไปที่ email ──────────────────────────────────────
authRouter.post("/login", async (req: Request, res: Response) => {
  try {

    // รับ Email และ Password
    const email = parseEmail(req.body.email);
    const { password } = req.body;
    if (!email || typeof password !== "string") {
      return res.status(400).json({ error: "อีเมลหรือรหัสผ่านไม่ถูกต้อง" });
    }

    // ค้นหา User จาก Email
    const [existingUser] = await db
      .select()
      .from(users)
      .where(userEmailEquals(email));

    // เทียบรหัสผ่านเสมอ (ถ้าไม่พบ user ใช้ hash จำลอง) → เวลาตอบกลับเท่ากันทั้งสองกรณี
    const isMatch = await bcryptjs.compare(password, existingUser?.password ?? DUMMY_PASSWORD_HASH);
    if (!existingUser || !isMatch) {
      return res.status(400).json({ error: "อีเมลหรือรหัสผ่านไม่ถูกต้อง" });
    }

    // ส่ง OTP ไป Email (ใช้อีเมลจาก DB)
    const { hash, refCode } = await sendOTP({ email: existingUser.email, purpose: "login" });

    // ก่อนยืนยัน OTP ส่งกลับแค่ email เท่านั้น
    res.json({
      message: "OTP sent to email",
      hash,
      ref_code: refCode,
      tempUser: { email: existingUser.email },
    });

  } catch (error) {
    return sendOtpError(res, error, "เกิดข้อผิดพลาดในการเข้าสู่ระบบ", "error");
  }
});


/// ── ขอ OTP Login ใหม่ (ต้องแนบ hash เดิมที่ได้จาก /login มาด้วย) ──────────────
authRouter.post("/login/resend_otp", async (req: Request, res: Response) => {
  try {
    const email = parseEmail(req.body.email);
    const { hash } = req.body;
    if (!email || !isNonEmptyString(hash)) {
      return res.status(400).json({ message: "ข้อมูลไม่ครบถ้วน" });
    }

    // อนุญาตเฉพาะคนที่ผ่านขั้นตอน email + password มาแล้วเท่านั้น
    const known = await isKnownChallenge({ email, hash, purpose: "login" });
    if (!known) {
      return res.status(400).json({ message: "กรุณาเข้าสู่ระบบใหม่อีกครั้ง" });
    }

    const { hash: newHash, refCode } = await sendOTP({ email, purpose: "login" });
    res.status(200).json({ success: true, hash: newHash, ref_code: refCode });
  } catch (error) {
    return sendOtpError(res, error, "ส่ง OTP ไม่สำเร็จ");
  }
});


/// ── ตรวจสอบ OTP (Login) ──────────────────────────────────────
authRouter.post("/login/verify_otp", async (req: Request, res: Response) => {
    try {
        const email = parseEmail(req.body.email);
        const { otp, hash } = req.body;

        if (!email || !isNonEmptyString(otp) || !isNonEmptyString(hash)) {
            return res.status(400).json({ message: "ข้อมูลไม่ครบถ้วน" });
        }

        const otpResult = await verifyOTP({ email, otp, hash, purpose: "login" });
        if (!otpResult.ok) {
            return sendOtpVerifyFail(res, otpResult);
        }

        // ดึง user จาก email ที่ยืนยัน OTP ผ่านแล้วเท่านั้น
        const [user] = await db.select().from(users).where(userEmailEquals(email));
        if (!user) {
          return res.status(404).json({ message: "ไม่พบผู้ใช้งาน" });
        }

        // สร้าง JWT ด้วย id ที่มาจาก DB
        const token = jwt.sign(
          { id: user.id },
          process.env.ACCESS_TOKEN_SECRET!,
          { expiresIn: "7d" }
        );

        res.json({ token, ...sanitizeUser(user) });

    } catch (error) {
        res.status(500).json({ message: "ยืนยัน OTP ล้มเหลว" });
    }
});


/// ── Reset Password ด้วย Email >> ส่ง OTP ──────────────────────
authRouter.post("/login/reset_password/send_otp", async (req: Request, res: Response) => {
  try {
    const email = parseEmail(req.body.email);
    if (!email) return res.status(400).json({ message: "รูปแบบอีเมลไม่ถูกต้อง" });

    const [existingUser] = await db
      .select({ email: users.email })
      .from(users)
      .where(userEmailEquals(email));

    // ไม่พบอีเมล >> สร้าง challenge จริงแต่ไม่ส่งเมล จึงใช้หน้านี้เดาไม่ได้ว่าอีเมลนี้มีในระบบหรือไม่
    const { hash, refCode } = await sendOTP({
      email: existingUser?.email ?? email,
      purpose: "reset_password",
      deliver: !!existingUser,
    });
    res.status(200).json({ success: true, hash, ref_code: refCode });
  } catch (error) {
    return sendOtpError(res, error, "ส่ง OTP ไม่สำเร็จ");
  }
});


/// ── Reset Password ด้วย Email >> ยืนยัน OTP และเปลี่ยนรหัสผ่าน ──────────────────────
authRouter.post("/login/reset_password/verify_and_reset", async (req: Request, res: Response) => {
  try {

    const email = parseEmail(req.body.email);
    const { otp, hash, new_password } = req.body;

    if (!email || !isNonEmptyString(otp) || !isNonEmptyString(hash) || typeof new_password !== "string") {
      return res.status(400).json({ message: "ข้อมูลไม่ครบถ้วน" });
    }

    if (new_password.length < MIN_PASSWORD_LENGTH) {
      return res.status(400).json({ message: `รหัสผ่านต้องมีอย่างน้อย ${MIN_PASSWORD_LENGTH} ตัวอักษร` });
    }

    const otpResult = await verifyOTP({ email, otp, hash, purpose: "reset_password" });
    if (!otpResult.ok) {
      return sendOtpVerifyFail(res, otpResult);
    }

    const hashedPassword = await bcryptjs.hash(new_password, 10);

    await db.transaction(async (tx) => {
      
      // Update password
      const [updatedUser] = await tx
        .update(users)
        .set({ password: hashedPassword })
        .where(userEmailEquals(email))
        .returning();
 
      if (!updatedUser) throw new Error("ไม่พบผู้ใช้งาน");
 
      // Insert users_history
      await tx.insert(usersHistory).values({
        user_id: updatedUser.id,
        user_updated: updatedUser.id,
        time_user_updated: sql`now()`,
      });
    });

    res.status(200).json({ message: "เปลี่ยนรหัสผ่านสำเร็จ" });
  } catch (e) {
    res.status(500).json({ message: "เปลี่ยนรหัสผ่านไม่สำเร็จ" });
  }
});



/* ============================================================
   3) ส่วนจัดการ User ที่กำลัง Login อยู่
============================================================ */

/// ── เรียกข้อมูล User ที่กำลัง Login อยู่ ──────────────────────────────────────
authRouter.get("/user_data", auth, async (req: AuthRequest, res) => {
    try {
        // เช็กว่า middleware ส่ง user มาให้หรือไม่
        if (!req.user) {
            res.status(401).json({ error: "ไม่พบผู้ใช้งาน" });
            return;
        }

        // ดึงข้อมูล user ปัจจุบันจาก DB
        const [user] = await db.select().from(users).where(eq(users.id, req.user));

        // ส่งข้อมูล user กลับไป
        if (!user) {
          return res.status(404).json({ error: "ไม่พบผู้ใช้งาน" });
        }
        res.json({ ...sanitizeUser(user), token: req.token });
    } catch (e) {
        res.status(500).json(false);
    }

});


/// ── Profile Edit >> update ข้อมูล User ──────────────────────────────────────
authRouter.put("/update_user", 
  auth, 
  (req: AuthRequest, res: Response, next) => {
    uploadFields(req, res, (err: any) => {
      if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
          return res.status(400).json({ error: `ไฟล์รูปภาพห้ามมีขนาดเกิน ${MAX_IMAGE_SIZE_MB}MB` });
        }
        return res.status(400).json({ error: err.message });
      } else if (err) {
        return res.status(400).json({ error: err.message });
      }
      next();
    });
  },
  async (req: AuthRequest, res: Response, next) => {
    const files = req.files as { [fieldname: string]: Express.Multer.File[] } | undefined;
 
    const candidates = [
      files?.['profile_image']?.[0],
      files?.['signature_image']?.[0],
    ].filter(Boolean) as Express.Multer.File[];
 
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

    const imageError = await normalizeUserImages(candidates);
    if (imageError) return res.status(400).json({ error: imageError });

    next();
  },
  async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.user!;
    const files = req.files as { [fieldname: string]: Express.Multer.File[] } | undefined;

    const {
      title_name, first_name, last_name, phone,
      job_position, job_level, job_office, job_department,
    } = req.body;

    const result = await db.transaction(async (tx) => {

      // ดึงข้อมูลเดิม
      const [currentUser] = await tx
        .select({ profile_img: users.profile_img, signature: users.signature })
        .from(users)
        .where(eq(users.id, userId));

      const updateValues: Record<string, any> = {
        title_name, 
        first_name, 
        last_name, 
        phone,

        job_position:   emptyToNull(job_position),
        job_level:      emptyToNull(job_level),
        job_office:     emptyToNull(job_office),
        job_department: emptyToNull(job_department),
      };

      // จัดการ profile_image
      const profileFile = files?.['profile_image']?.[0];
      if (profileFile) {
        const ext = path.extname(profileFile.originalname);
        const newFileName = `${userId}_profile_img_${Date.now()}${ext}`; // ตั้งชื่อรูป
        const newPath = path.join(uploadDir, newFileName);
        fs.renameSync(profileFile.path, newPath);

        if (currentUser?.profile_img) {
          const oldPath = path.join(uploadDir, currentUser.profile_img);
          if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
        }
        updateValues['profile_img'] = newFileName;
      }

      // จัดการ signature_image
      const signatureFile = files?.['signature_image']?.[0];
      if (signatureFile) {
        const ext = path.extname(signatureFile.originalname);
        const newFileName = `${userId}_signature_img_${Date.now()}${ext}`; // ตั้งชื่อรูป
        const newPath = path.join(signatureDir, newFileName);
        fs.renameSync(signatureFile.path, newPath);

        if (currentUser?.signature) {
          const oldPath = path.join(signatureDir, currentUser.signature);
          if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
        }
        updateValues['signature'] = newFileName;
      }

      // Update users
      const [updatedUser] = await tx
        .update(users)
        .set(updateValues)
        .where(eq(users.id, userId))
        .returning();

      if (!updatedUser) throw new Error("ไม่พบ user");

      // Insert users_history
      await tx.insert(usersHistory).values({
        user_id:           userId,
        user_updated: userId,
        time_user_updated: sql`now()`,
      });

      return updatedUser;
    });

    res.status(200).json({ ...sanitizeUser(result), token: req.token });
  } catch (e) {
    console.error("[PUT /update_user] error:", e);
    // ลบไฟล์ที่ upload มาถ้า error
    const files = req.files as { [fieldname: string]: Express.Multer.File[] } | undefined;
    files?.['profile_image']?.[0] && fs.existsSync(files['profile_image'][0].path) && fs.unlinkSync(files['profile_image'][0].path);
    files?.['signature_image']?.[0] && fs.existsSync(files['signature_image'][0].path) && fs.unlinkSync(files['signature_image'][0].path);
    res.status(500).json({ error: "แก้ไขข้อมูลไม่สำเร็จ" });
  }
});


/// ── Reset Password (ยืนยันด้วยรหัสผ่านปัจจุบัน, ต้อง login) ──────────
authRouter.put("/profile/reset_password", auth, async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.user!;
    const { current_password, new_password } = req.body;

    if (!current_password || !new_password) {
      return res.status(400).json({ message: "ข้อมูลไม่ครบถ้วน" });
    }

    const [existingUser] = await db
      .select()
      .from(users)
      .where(eq(users.id, userId));

    if (!existingUser) {
      return res.status(404).json({ message: "ไม่พบผู้ใช้งาน" });
    }

    const isMatch = await bcryptjs.compare(current_password, existingUser.password);
    if (!isMatch) {
      return res.status(400).json({ message: "รหัสผ่านปัจจุบันไม่ถูกต้อง" });
    }

    const hashedPassword = await bcryptjs.hash(new_password, 10);

    await db.transaction(async (tx) => {

      // Update password
      await tx
        .update(users)
        .set({ password: hashedPassword })
        .where(eq(users.id, userId));

      // Insert users_history
      await tx.insert(usersHistory).values({
        user_id:           userId,
        user_updated: userId,
        time_user_updated: sql`now()`,
      });
    });

    res.status(200).json({ message: "เปลี่ยนรหัสผ่านสำเร็จ" });
  } catch (e) {
    console.log(e);
    res.status(500).json({ message: "เปลี่ยนรหัสผ่านไม่สำเร็จ" });
  }
});



/* ============================================================
   4) User Management (admin)
============================================================ */

/// ── เรียกข้อมูล User ที่ผ่านการอนุมัติแล้ว (ใช้ me.admin เป็นตัวกรอง ทั้ง admin และ user) ─────────────────────────
authRouter.get("/all_approved_users", auth, async (req: AuthRequest, res: Response) => {
  try {

    // ดึงข้อมูล user ที่ login อยู่
    const [me] = await db
      .select({ id: users.id, admin: users.admin })
      .from(users)
      .where(eq(users.id, req.user!));

    if (!me) {
      res.status(401).json({ error: "ไม่พบข้อมูลผู้ใช้" });
      return;
    }

    // ใช้ค่า me.admin ของตัวเองเป็นตัวกรอง
    if (!me.admin) {
      res.status(400).json({ error: "สมาชิกยังไม่ผ่านการอนุมัติ" });
      return;
    }

    const groupUsers = await db
      .select({

        id: users.id,

        title_name: users.title_name,
        first_name: users.first_name,
        last_name: users.last_name,
        phone: users.phone,
        email: users.email,

        profile_img: users.profile_img,

        job_position: users.job_position,
        job_level: users.job_level,
        job_office: users.job_office,
        job_department: users.job_department,

        admin: users.admin,
        status: users.status,
        signature: users.signature,

      })
      .from(users)
      .where(eq(users.admin, me.admin)) // กรองเฉพาะ me.admin เดียวกัน
      .orderBy(asc(users.email));       // เรียง a-z ตาม email

    res.status(200).json(groupUsers);
  } catch (e) {
    console.error("[GET /users] error:", e);
    res.status(500).json({ error: "ไม่สามารถดึงข้อมูลสมาชิกได้" });
  }
});


// ── ดึงข้อมูล user ตาม id  ─────────────────────────
authRouter.get("/users_by_ids", auth, async (req: AuthRequest, res: Response) => {
  try {
    const idsParam = (req.query["ids"] as string) ?? "";
    const ids = [...new Set(
      idsParam.split(",").map((s) => parseInt(s.trim())).filter((n) => !isNaN(n))
    )];

    if (ids.length === 0) {
      res.status(200).json([]);
      return;
    }

    const [me] = await db
      .select({ id: users.id, status: users.status, admin: users.admin })
      .from(users)
      .where(eq(users.id, req.user!));

    if (!me) {
      res.status(401).json({ error: "ไม่พบข้อมูลผู้ใช้" });
      return;
    }

    // หา admin
    const myAdminId = me.status === "admin" ? me.id : (me.admin ? parseInt(me.admin) : null);

    if (!myAdminId) {
      res.status(400).json({ error: "สมาชิกยังไม่ผ่านการอนุมัติ" });
      return;
    }

    // จำกัดเฉพาะ id ที่เคยอยู่ในกลุ่มของ admin นี้ (ปัจจุบัน หรือเคยอนุมัติ/ถอนอนุมัติมาก่อน)
    const historyRows = await db
      .select({ user_id: usersHistory.user_id })
      .from(usersHistory)
      .where(
        and(
          inArray(usersHistory.user_id, ids),
          or(
            eq(usersHistory.admin_approved_user, myAdminId),
            eq(usersHistory.admin_revoke_approval_user, myAdminId)
          )
        )
      );

    const allowedIds = new Set<number>([myAdminId, ...historyRows.map((r) => r.user_id)]);
    const filteredIds = ids.filter((id) => allowedIds.has(id));

    if (filteredIds.length === 0) {
      res.status(200).json([]);
      return;
    }

    const foundUsers = await db
      .select({
        id: users.id,
        title_name: users.title_name,
        first_name: users.first_name,
        last_name: users.last_name,
        phone: users.phone,
        email: users.email,
        profile_img: users.profile_img,
        job_position: users.job_position,
        job_level: users.job_level,
        job_office: users.job_office,
        job_department: users.job_department,
        admin: users.admin,
        status: users.status,
        signature: users.signature,
      })
      .from(users)
      .where(inArray(users.id, filteredIds));

    res.status(200).json(foundUsers);
  } catch (e) {
    console.error("[GET /users_by_ids] error:", e);
    res.status(500).json({ error: "ไม่สามารถเรียกข้อมูลสมาชิกได้" });
  }
});


// ── สำหรับ admin >> ค้นหา user ที่ยังไม่ได้รับการอนุมัติ ──────────────────
authRouter.get("/search_users", auth, requireAdmin, async (req: AuthRequest, res: Response) => {
  try {
    const adminId = req.user!;
    const query   = (req.query["q"] as string ?? "").toLowerCase().trim();

    // เฉพาะผู้ที่ยังไม่สังกัดกลุ่มใดและยังไม่ได้รับอนุมัติ
    const allUsers = await db
      .select({
        id: users.id,

        title_name: users.title_name,
        first_name: users.first_name,
        last_name: users.last_name,
        email: users.email,

        profile_img: users.profile_img,

        job_position: users.job_position,
        job_level: users.job_level,
        job_office: users.job_office,
        job_department: users.job_department,
      })
      .from(users)
      .where(
        and(
          sql`${users.admin} IS NULL`,
          sql`${users.status} IS NULL`,
          ne(users.id, adminId)
        )
      )
      .orderBy(asc(users.email))
      .limit(200);

    // กรองตาม query (first_name, last_name, email)
    const filtered = query
      ? allUsers.filter((u) =>
          `${u.first_name} ${u.last_name}`.toLowerCase().includes(query) ||
          u.email.toLowerCase().includes(query)
        )
      : allUsers;

    res.status(200).json(filtered);
  } catch (e) {
    console.error("[GET /search_users] error:", e);
    res.status(500).json({ error: "ค้นหาสมาชิกไม่สำเร็จ" });
  }
});


// ── สำหรับ admin >> อนุมัติ user ──────────────────────────────────────────────
authRouter.put("/approved_user/:userId", auth, async (req: AuthRequest, res: Response) => {
  try {
    const adminId = req.user!;
    const userId  = parseInt(req.params["userId"] as string);

    if (isNaN(userId) || userId <= 0) {
      res.status(400).json({ error: "userId ไม่ถูกต้อง" });
      return;
    }

    // อนุมัติตัวเองไม่ได้ (ป้องกัน admin เปลี่ยนสถานะตัวเองเป็น user)
    if (userId === adminId) {
      res.status(400).json({ error: "ไม่สามารถอนุมัติบัญชีของตัวเองได้" });
      return;
    }

    // ตรวจสอบว่าเป็น admin จริง
    const [admin] = await db
      .select({ id: users.id, status: users.status })
      .from(users)
      .where(eq(users.id, adminId));

    if (!admin || admin.status !== "admin") {
      res.status(403).json({ error: "ไม่มีสิทธิ์ในการอนุมัติสมาชิก" });
      return;
    }

    // เป้าหมายต้องยังไม่สังกัดกลุ่ม (admin = null) และยังไม่มีสถานะ (status = null)
    const [target] = await db
      .select({ id: users.id, admin: users.admin, status: users.status })
      .from(users)
      .where(eq(users.id, userId));

    if (!target) {
      res.status(404).json({ error: "ไม่พบสมาชิกที่ต้องการอนุมัติ" });
      return;
    }

    if (target.status === "admin") {
      res.status(403).json({ error: "ไม่สามารถอนุมัติบัญชีผู้ดูแลระบบได้" });
      return;
    }

    if (target.admin !== null || target.status !== null) {
      res.status(409).json({ error: "สมาชิกผ่านการอนุมัติหรือสังกัดกลุ่มอื่นแล้ว" });
      return;
    }

    await db.transaction(async (tx) => {

      // Update users >> ใส่ admin id และเปลี่ยน status เป็น "user"
      const [updated] = await tx
        .update(users)
        .set({
          admin:  String(adminId),
          status: "user",
        })
        .where(and(
          eq(users.id, userId),
          isNull(users.admin),
          isNull(users.status),
          ne(users.id, adminId),
        ))
        .returning({ id: users.id });

      if (!updated) {
        throw new Error("สมาชิกผ่านการอนุมัติหรือสังกัดกลุ่มอื่นแล้ว");
      }

      // Insert users_history
      await tx.insert(usersHistory).values({
        user_id:             userId,
        admin_approved_user: adminId,
        time_admin_approved_user: sql`now()`,
      });
    });

    res.status(200).json({ message: "อนุมัติสมาชิกสำเร็จ" });
  } catch (e) {
    // สถานะเป้าหมายเปลี่ยนระหว่างตรวจกับ update (เช่น admin อีกคนอนุมัติไปก่อน)
    if (e instanceof Error && e.message === "สมาชิกผ่านการอนุมัติหรือสังกัดกลุ่มอื่นแล้ว") {
      res.status(409).json({ error: e.message });
      return;
    }
    console.error("[PUT /approved_user] error:", e);
    res.status(500).json({ error: "อนุมัติสมาชิกไม่สำเร็จ" });
  }
});


// ── สำหรับ admin >> ยกเลิกการอนุมัติ user ──────────────────────────────────────────────
authRouter.put("/revoke_approval_user/:userId", auth, async (req: AuthRequest, res: Response) => {
  try {
    const adminId = req.user!;
    const userId  = parseInt(req.params["userId"] as string);

    if (isNaN(userId)) {
      res.status(400).json({ error: "userId ไม่ถูกต้อง" });
      return;
    }

    // ตรวจสอบว่าเป็น admin จริง
    const [admin] = await db
      .select({ id: users.id, status: users.status })
      .from(users)
      .where(eq(users.id, adminId));

    if (!admin || admin.status !== "admin") {
      res.status(403).json({ error: "ไม่มีสิทธิ์ยกเลิกการอนุมัติสมาชิก" });
      return;
    }

    // user ต้องสังกัด admin นี้เท่านั้น
    const [target] = await db
      .select({ id: users.id, admin: users.admin })
      .from(users)
      .where(eq(users.id, userId));

    if (!target) {
      res.status(404).json({ error: "ไม่พบสมาชิกที่ต้องการยกเลิกการอนุมัติ" });
      return;
    }

    if (target.admin !== String(adminId)) {
      res.status(403).json({ error: "ไม่มีสิทธิ์ยกเลิกการอนุมัติสมาชิกรายนี้" });
      return;
    }

    await db.transaction(async (tx) => {

      // Update users: ล้าง admin และ status
      const [updated] = await tx
        .update(users)
        .set({
          admin:  null,
          status: null,
        })
        .where(and(eq(users.id, userId), eq(users.admin, String(adminId))))
        .returning({ id: users.id });

      if (!updated) {
        throw new Error("สมาชิกถูกยกเลิกการอนุมัติแล้วโดยผู้อื่น");
      }

      // Insert users_history
      await tx.insert(usersHistory).values({
        user_id:                userId,
        admin_revoke_approval_user: adminId,
        time_admin_revoke_approval_user: sql`now()`,
      });
    });

    res.status(200).json({ message: "ยกเลิกการอนุมัติสมาชิกสำเร็จ" });
  } catch (e) {
    console.error("[PUT /approved_user] error:", e);
    res.status(500).json({ error: "ยกเลิกการอนุมัติสมาชิกไม่สำเร็จ" });
  }
});




/* ============================================================
   5) ส่งไฟล์รูปโปรไฟล์ / ลายเซ็น (ต้อง login)
============================================================ */
const PROFILE_ROOT   = path.resolve(uploadDir);
const SIGNATURE_ROOT = path.resolve(signatureDir);

// ลักษณะชื่อไฟล์
function isPlainFilename(name: string): boolean {
  return !!name && path.basename(name) === name && !name.startsWith(".");
}

function sendImageFile(res: Response, root: string, filename: string, cacheControl: string) {
  res.set("Cache-Control", cacheControl);
  res.set("X-Content-Type-Options", "nosniff");
  res.sendFile(path.join(root, filename), { dotfiles: "deny" }, (err) => {
    if (err && !res.headersSent) {
      res.status(404).json({ error: "ไม่พบรูปภาพ" });
    }
  });
}

/// ─── ตรวจสอบสิทธิ์ลายเซ็นของ user ────────────────────────────
async function canViewSignature(viewerId: number, ownerId: number): Promise<boolean> {
  if (viewerId === ownerId) return true;

  const [me] = await db
    .select({ status: users.status, admin: users.admin })
    .from(users)
    .where(eq(users.id, viewerId));

  if (!me) return false;

  const myAdminId = me.status === "admin" ? viewerId : (me.admin ? parseInt(me.admin) : null);
  if (!myAdminId || isNaN(myAdminId)) return false;

  if (ownerId === myAdminId) return true;

  const [row] = await db
    .select({ id: usersHistory.id })
    .from(usersHistory)
    .where(
      and(
        eq(usersHistory.user_id, ownerId),
        or(
          eq(usersHistory.admin_approved_user, myAdminId),
          eq(usersHistory.admin_revoke_approval_user, myAdminId)
        )
      )
    )
    .limit(1);

  return !!row;
}


/// ── รูปโปรไฟล์: ผู้ใช้ที่ login ─────────────────────────────
authRouter.get("/image/profile/:filename", auth, async (req: AuthRequest, res: Response) => {
  try {
    const filename = String(req.params["filename"] ?? "");
    if (!isPlainFilename(filename)) {
      res.status(400).json({ error: "คำขอไม่ถูกต้อง" });
      return;
    }

    // ต้องเป็นชื่อไฟล์ที่บันทึกเป็น profile ของ user
    const [owner] = await db
      .select({ id: users.id })
      .from(users)
      .where(eq(users.profile_img, filename))
      .limit(1);

    if (!owner) {
      res.status(404).json({ error: "ไม่พบรูปภาพ" });
      return;
    }

    sendImageFile(res, PROFILE_ROOT, filename, "private, max-age=300");
  } catch (e) {
    console.error("[GET /image/profile] error:", e);
    if (!res.headersSent) res.status(500).json({ error: "ดึงข้อมูลรูปภาพไม่สำเร็จ" });
  }
});


/// ── ลายเซ็น: user หรือคนในกลุ่ม admin เดียวกัน ─────────────────
authRouter.get("/image/signature/:filename", auth, async (req: AuthRequest, res: Response) => {
  try {
    const filename = String(req.params["filename"] ?? "");
    if (!isPlainFilename(filename)) {
      res.status(400).json({ error: "คำขอไม่ถูกต้อง" });
      return;
    }

    const [owner] = await db
      .select({ id: users.id })
      .from(users)
      .where(eq(users.signature, filename))
      .limit(1);

    // ไม่พบ หรือไม่มีสิทธิ์
    if (!owner || !(await canViewSignature(req.user!, owner.id))) {
      res.status(404).json({ error: "ไม่พบรูปภาพ" });
      return;
    }

    sendImageFile(res, SIGNATURE_ROOT, filename, "private, no-store");
  } catch (e) {
    console.error("[GET /image/signature] error:", e);
    if (!res.headersSent) res.status(500).json({ error: "ดึงข้อมูลรูปภาพไม่สำเร็จ" });
  }
});



export default authRouter;