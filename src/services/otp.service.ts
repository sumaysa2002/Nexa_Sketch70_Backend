import crypto from "crypto";
import { and, asc, desc, eq, gt, gte, isNull, lt, max, sql } from "drizzle-orm";
import { db } from "../db/index.js";
import { otpChallenges } from "../db/schema.js";
import { sendOTPEmail } from "./emailer.service.js";

/* ============================================================
   CONFIG
============================================================ */
const OTP_SECRET = process.env.OTP_SECRET;
// ไม่มี fallback อีกต่อไป: ถ้า secret ไม่มี/สั้นเกินไป ให้ server ไม่ start เลย
if (!OTP_SECRET || OTP_SECRET.length < 32) {
  throw new Error("OTP_SECRET ต้องถูกตั้งค่าและยาวอย่างน้อย 32 ตัวอักษร");
}

const EXPIRE_MINUTES    = Number(process.env.OTP_EXPIRE_MINUTES) || 5;  // อายุ OTP
export const MAX_OTP_ATTEMPTS = 5;                                      // เดาผิดได้กี่ครั้งต่อ 1 OTP
const RESEND_COOLDOWN_S = 60;                                           // ขอ OTP ใหม่ได้ทุกกี่วินาที

// โควตาการขอ OTP (ต่ออีเมล + purpose) — เริ่มนับใหม่ทุกครั้งที่ยืนยัน OTP สำเร็จ (ทุก purpose ของอีเมลนั้น)
const MAX_SENDS_PER_BATCH   = 5;   // ขอได้กี่ครั้งต่อรอบ
const BATCH_BLOCK_MINUTES   = 15;  // ขอครบรอบแล้วต้องรอกี่นาที (นับจากครั้งสุดท้ายของรอบ)
const MAX_SENDS_PER_DAY     = 20;  // เพดานใน 24 ชม.
const DAY_MS = 24 * 60 * 60 * 1000;

export type OtpPurpose = "signup" | "login" | "reset_password";

/** error ที่ route ควรส่งกลับไปให้ client ตาม status */
export class OtpError extends Error {
  constructor(
    public status: number,
    message: string,
    public retryAfterSeconds?: number // 429: ต้องรออีกกี่วินาทีถึงขอใหม่ได้ (ให้แอปนับถอยหลัง)
  ) {
    super(message);
  }
}

/* ============================================================
   HELPERS
============================================================ */
const normalizeEmail = (email: string) => email.trim().toLowerCase();

// ผูก OTP เข้ากับ challenge id + email + purpose → เอา OTP ไปใช้ข้าม flow ไม่ได้
const hmacOtp = (id: string, email: string, purpose: OtpPurpose, otp: string) =>
  crypto.createHmac("sha256", OTP_SECRET).update(`${id}:${email}:${purpose}:${otp}`).digest();

/**
 * รหัสอ้างอิง (Ref) ของ OTP แต่ละรอบ = 6 ตัวแรกของ challengeId (ตัวพิมพ์ใหญ่)
 * แสดงทั้งในอีเมลและหน้า OTP ให้ผู้ใช้จับคู่ได้ว่าใช้รหัสจากอีเมลฉบับไหน
 * (Flutter คำนวณแบบเดียวกันจาก hash ได้เอง)
 */
export const refCodeFromId = (id: string) => id.slice(0, 6).toUpperCase();

/** error 429 พร้อมบอกว่าต้องรออีกกี่นาที */
const quotaError = (retryAt: Date, now: Date) => {
  const minutes = Math.max(1, Math.ceil((retryAt.getTime() - now.getTime()) / 60000));
  const waitText =
    minutes >= 60
      ? `${Math.floor(minutes / 60)} ชั่วโมง${minutes % 60 ? ` ${minutes % 60} นาที` : ""}`
      : `${minutes} นาที`;
  const waitS = Math.max(1, Math.ceil((retryAt.getTime() - now.getTime()) / 1000));
  return new OtpError(429, `ขอรหัส OTP ครบจำนวนครั้งที่กำหนดแล้ว กรุณารออีก ${waitText} แล้วลองใหม่`, waitS);
};

// OTP 6 หลักจาก CSPRNG (ไม่ใช้ otp-generator แล้ว)
const generateOtp = () => crypto.randomInt(0, 1_000_000).toString().padStart(6, "0");

/* ============================================================
   ส่ง OTP
   คืนค่า hash (= challengeId) และ refCode
   deliver = false → สร้าง challenge แต่ไม่ส่งอีเมล
     (ใช้กับอีเมลที่ไม่มีในระบบ ให้ response และพฤติกรรมเหมือนกรณีปกติทุกอย่าง)
============================================================ */
export const sendOTP = async ({
  email,
  purpose,
  deliver = true,
}: {
  email: string;
  purpose: OtpPurpose;
  deliver?: boolean;
}): Promise<{ hash: string; refCode: string }> => {
  const normEmail = normalizeEmail(email);
  const now = new Date();

  // 1. Rate limit ต่ออีเมล + purpose (กันยิงเมลถล่ม / เปลือง quota Gmail)
  const [last] = await db
    .select({ created_at: otpChallenges.created_at })
    .from(otpChallenges)
    .where(and(eq(otpChallenges.email, normEmail), eq(otpChallenges.purpose, purpose)))
    .orderBy(desc(otpChallenges.created_at))
    .limit(1);

  if (last && now.getTime() - last.created_at.getTime() < RESEND_COOLDOWN_S * 1000) {
    const waitS = Math.ceil((RESEND_COOLDOWN_S * 1000 - (now.getTime() - last.created_at.getTime())) / 1000);
    throw new OtpError(429, `กรุณารอ ${waitS} วินาทีก่อนขอรหัส OTP ใหม่`, waitS);
  }

  // 1.1 จุดเริ่มนับ = การยืนยัน OTP สำเร็จครั้งล่าสุดของอีเมลนี้ (purpose ใดก็ได้)
  //     แถวเก่ายังอยู่เป็นประวัติ แต่ไม่ถูกนับโควตาแล้ว
  const [anchorRow] = await db
    .select({ value: max(otpChallenges.verified_at) })
    .from(otpChallenges)
    .where(eq(otpChallenges.email, normEmail));

  const dayAgo = new Date(now.getTime() - DAY_MS);
  const anchor = anchorRow?.value && anchorRow.value > dayAgo ? anchorRow.value : dayAgo;

  // 1.2 ครั้งที่ขอไปแล้ว (หลังจุดเริ่มนับ และภายใน 24 ชม.) เรียงจากเก่า → ใหม่
  const sends = await db
    .select({ created_at: otpChallenges.created_at })
    .from(otpChallenges)
    .where(
      and(
        eq(otpChallenges.email, normEmail),
        eq(otpChallenges.purpose, purpose),
        gt(otpChallenges.created_at, anchor)
      )
    )
    .orderBy(asc(otpChallenges.created_at));

  // 1.3 เพดานรายวัน: ขอได้อีกครั้งเมื่อครั้งที่เก่าที่สุดในกลุ่ม 20 ครั้งล่าสุดครบ 24 ชม.
  if (sends.length >= MAX_SENDS_PER_DAY) {
    const oldest = sends[sends.length - MAX_SENDS_PER_DAY]!.created_at;
    throw quotaError(new Date(oldest.getTime() + DAY_MS), now);
  }

  // 1.4 รอบละ 5 ครั้ง: ไล่นับทีละรอบ ถ้ารอบปัจจุบันครบ 5 แล้วยังไม่พ้น 15 นาที → บล็อก
  let inBatch = 0;
  let lastSend: Date | null = null;
  for (const { created_at } of sends) {
    if (inBatch === MAX_SENDS_PER_BATCH) inBatch = 0; // ครั้งแรกหลังพ้นช่วงรอ = เริ่มรอบใหม่
    inBatch++;
    lastSend = created_at;
  }

  if (inBatch === MAX_SENDS_PER_BATCH && lastSend) {
    const unblockAt = new Date(lastSend.getTime() + BATCH_BLOCK_MINUTES * 60 * 1000);
    if (now < unblockAt) throw quotaError(unblockAt, now);
  }

  // 2. ยกเลิก OTP เก่าที่ยังไม่ได้ใช้ (ให้มีได้แค่ตัวล่าสุดตัวเดียว)
  await db
    .update(otpChallenges)
    .set({ consumed_at: now })
    .where(
      and(
        eq(otpChallenges.email, normEmail),
        eq(otpChallenges.purpose, purpose),
        isNull(otpChallenges.consumed_at)
      )
    );

  // 3. สร้าง challenge ใหม่ (เก็บแค่ HMAC ของ OTP)
  const id = crypto.randomBytes(32).toString("hex");
  const otp = generateOtp();

  await db.insert(otpChallenges).values({
    id,
    email: normEmail,
    purpose,
    otp_hash: hmacOtp(id, normEmail, purpose, otp).toString("hex"),
    expires_at: new Date(now.getTime() + EXPIRE_MINUTES * 60 * 1000),
  });

  const refCode = refCodeFromId(id);

  // แสดงรหัสใน Terminal
  console.log("-----------------------------------------");
  console.log(`[OTP DEBUG] Target Email: ${email}`);
  console.log(`[OTP DEBUG] รหัสอ้างอิง คือ: ${refCode}`);
  console.log(`[OTP DEBUG] รหัส OTP คือ: ${otp}`);

  // 4. ส่งอีเมล
  if (deliver) {
    try {
      await sendOTPEmail({ email: normEmail, otp, refCode, expiresIn: EXPIRE_MINUTES });
    } catch (error) {
      await db.delete(otpChallenges).where(eq(otpChallenges.id, id));
      console.error("[EMAIL ERROR] ส่ง OTP ไม่สำเร็จ:", (error as Error).message);
      throw new OtpError(502, "ไม่สามารถส่งอีเมล OTP ได้ กรุณาลองใหม่อีกครั้ง");
    }
  }

  return { hash: id, refCode };
};

/* ============================================================
   ตรวจสอบ OTP
   - ใช้ได้ครั้งเดียว (consumed_at)
   - เดาผิดได้ไม่เกิน MAX_OTP_ATTEMPTS ครั้ง
   - ต้องตรงทั้ง email และ purpose
   คืนผลแบบละเอียด ให้หน้า OTP แสดงจำนวนครั้งที่กรอกไปแล้วได้
============================================================ */
export type OtpVerifyReason =
  | "ok"
  | "invalid"   // รหัสผิด (ยังกรอกต่อได้ ถ้า remaining > 0)
  | "locked"    // กรอกผิดครบจำนวนแล้ว
  | "expired"   // หมดอายุ
  | "unusable"; // ใช้ไปแล้ว / ถูกยกเลิกเพราะขอรหัสใหม่ / ไม่พบ

export interface OtpVerifyResult {
  ok: boolean;
  reason: OtpVerifyReason;
  attempts: number;     // จำนวนครั้งที่กรอกไปแล้ว (รวมครั้งนี้)
  maxAttempts: number;
  remaining: number;    // กรอกได้อีกกี่ครั้ง
  refCode: string | null;
}

const result = (
  reason: OtpVerifyReason,
  attempts: number,
  refCode: string | null
): OtpVerifyResult => ({
  ok: reason === "ok",
  reason,
  attempts,
  maxAttempts: MAX_OTP_ATTEMPTS,
  remaining: Math.max(0, MAX_OTP_ATTEMPTS - attempts),
  refCode,
});

export const verifyOTP = async ({
  email,
  otp,
  hash,
  purpose,
}: {
  email: string;
  otp: string;
  hash: string; // = challengeId (ชื่อฟิลด์เดิมเพื่อให้ Flutter ไม่ต้องแก้)
  purpose: OtpPurpose;
}): Promise<OtpVerifyResult> => {
  if (typeof hash !== "string" || !/^[0-9a-f]{64}$/.test(hash) || typeof email !== "string") {
    return result("unusable", 0, null);
  }

  const normEmail = normalizeEmail(email);
  const refCode = refCodeFromId(hash);
  const now = new Date();

  // 1. นับ attempt แบบ atomic ก่อนเทียบรหัส (กันยิงพร้อมกันหลาย request เพื่อเดาเกินโควตา)
  //    รหัสที่รูปแบบผิด (ไม่ใช่ตัวเลข 6 หลัก) ก็นับเป็น 1 ครั้งด้วย
  const [challenge] = await db
    .update(otpChallenges)
    .set({ attempts: sql`${otpChallenges.attempts} + 1` })
    .where(
      and(
        eq(otpChallenges.id, hash),
        eq(otpChallenges.email, normEmail),
        eq(otpChallenges.purpose, purpose),
        isNull(otpChallenges.consumed_at),
        gt(otpChallenges.expires_at, now),
        lt(otpChallenges.attempts, MAX_OTP_ATTEMPTS)
      )
    )
    .returning();

  // 2. ไม่ผ่านเงื่อนไข → ดูว่าเพราะอะไร
  if (!challenge) {
    const [row] = await db
      .select({
        attempts: otpChallenges.attempts,
        consumed_at: otpChallenges.consumed_at,
        expires_at: otpChallenges.expires_at,
      })
      .from(otpChallenges)
      .where(
        and(
          eq(otpChallenges.id, hash),
          eq(otpChallenges.email, normEmail),
          eq(otpChallenges.purpose, purpose)
        )
      )
      .limit(1);

    if (!row || row.consumed_at) return result("unusable", row?.attempts ?? 0, refCode);
    if (row.attempts >= MAX_OTP_ATTEMPTS) return result("locked", row.attempts, refCode);
    return result("expired", row.attempts, refCode);
  }

  // 3. เทียบแบบ constant-time
  const isFormatOk = typeof otp === "string" && /^\d{6}$/.test(otp);
  const expected = Buffer.from(challenge.otp_hash, "hex");
  const actual = hmacOtp(challenge.id, normEmail, purpose, isFormatOk ? otp : "");
  const match =
    isFormatOk && expected.length === actual.length && crypto.timingSafeEqual(expected, actual);

  if (!match) {
    return result(
      challenge.attempts >= MAX_OTP_ATTEMPTS ? "locked" : "invalid",
      challenge.attempts,
      refCode
    );
  }

  // 4. mark ว่าใช้แล้ว + ยืนยันสำเร็จ (ถ้ามี request อื่นใช้ไปก่อน จะได้ 0 แถว)
  //    verified_at = จุดเริ่มนับโควตาขอ OTP ใหม่ของอีเมลนี้
  const consumed = await db
    .update(otpChallenges)
    .set({ consumed_at: now, verified_at: now })
    .where(and(eq(otpChallenges.id, challenge.id), isNull(otpChallenges.consumed_at)))
    .returning({ id: otpChallenges.id });

  return result(consumed.length === 1 ? "ok" : "unusable", challenge.attempts, refCode);
};

/** ข้อความภาษาไทยสำหรับผลตรวจ OTP ที่ไม่ผ่าน */
export const otpFailureMessage = (r: OtpVerifyResult): string => {
  const ref = r.refCode ? ` [Ref: ${r.refCode}]` : "";
  switch (r.reason) {
    case "invalid":
      return `${ref} รหัส OTP ไม่ถูกต้อง กรอกได้อีก ${r.remaining} ครั้ง`;
    case "locked":
      return `${ref} กรอกรหัสผิดครบ ${r.maxAttempts} ครั้งแล้ว กรุณากดขอรหัส OTP ใหม่`;
    case "expired":
      return `${ref} รหัส OTP หมดอายุแล้ว กรุณากดขอรหัส OTP ใหม่`;
    default:
      return `${ref} รหัส OTP มีปัญหาหรือหมดอายุแล้ว กรุณากดขอรหัส OTP ใหม่`;
  }
};

/** ลบ challenge ที่หมดอายุเกิน 1 วัน (เรียกจาก cron หรือ setInterval ก็ได้) */
export const purgeOldOtpChallenges = () =>
  db
    .delete(otpChallenges)
    .where(lt(otpChallenges.expires_at, new Date(Date.now() - 24 * 60 * 60 * 1000)));

/**
 * เช็กว่า challengeId นี้เคยออกให้ email + purpose นี้จริง และสร้างไม่เกิน maxAgeMinutes
 * ใช้กับ "ขอ OTP Login ใหม่" → เฉพาะคนที่ผ่านขั้นตอนรหัสผ่านมาแล้วเท่านั้นที่ขอใหม่ได้
 */
export const isKnownChallenge = async ({
  email,
  hash,
  purpose,
  maxAgeMinutes = 30,
}: {
  email: string;
  hash: string;
  purpose: OtpPurpose;
  maxAgeMinutes?: number;
}): Promise<boolean> => {
  if (typeof hash !== "string" || !/^[0-9a-f]{64}$/.test(hash)) return false;
  if (typeof email !== "string") return false;

  const [row] = await db
    .select({ id: otpChallenges.id })
    .from(otpChallenges)
    .where(
      and(
        eq(otpChallenges.id, hash),
        eq(otpChallenges.email, normalizeEmail(email)),
        eq(otpChallenges.purpose, purpose),
        gte(otpChallenges.created_at, new Date(Date.now() - maxAgeMinutes * 60 * 1000))
      )
    )
    .limit(1);

  return !!row;
};

