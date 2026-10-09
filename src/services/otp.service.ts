import crypto from "crypto";
import otpGenerator from "otp-generator";
import { sendOTPEmail } from "./emailer.service.js";

/*
  ระบบ OTP แบบมีสถานะ (stateful) เก็บในหน่วยความจำของเซิร์ฟเวอร์

  - OTP แต่ละรอบ = 1 challenge มี ref (รหัสอ้างอิงที่แสดงในอีเมล), อีเมล, ประเภท, วันหมดอายุ, จำนวนครั้งที่เดาผิด
  - `hash` ที่คืนให้แอปยังมีรูปแบบเดิม (`<hex>.<expires>`) แอปไม่ต้องแก้ แต่ตอนนี้ใช้เป็นแค่ตัวอ้างถึง challenge
  - ประเภท "login"   = OTP ที่ออกหลังตรวจรหัสผ่านที่ /auth/login แล้ว ใช้ได้ที่ /auth/login/verify_otp เท่านั้น
    ประเภท "general" = OTP จาก /auth/signup/send_otp (ใช้ทั้งสมัครสมาชิกและรีเซ็ตรหัสผ่าน) ใช้ล็อกอินไม่ได้
  - เดาผิดครบ MAX_ATTEMPTS ครั้ง challenge นั้นถูกลบทิ้ง ถูกต้องแล้วใช้ได้ครั้งเดียว

  ปุ่ม Resend ของหน้า OTP login:
  แอปรุ่นเดิมกดแล้วเรียก /auth/signup/send_otp (ได้ OTP ประเภท general) แล้วเอาไปยืนยันที่ /auth/login/verify_otp
  ซึ่งเป็นช่องเดียวกับที่ผู้โจมตีใช้ จึงรับ OTP ประเภท general ที่ login ไม่ได้ (เว้นแต่เปิด OTP_ALLOW_GENERAL_AT_LOGIN ชั่วคราว)
  ทางที่ถูกคือ /auth/login/resend_otp: ขอรอบใหม่ได้เมื่อมี hash ของรอบ login เดิม (ซึ่งออกได้หลังผ่านรหัสผ่านเท่านั้น)
  challenge ประเภท login จึงถูกเก็บไว้เกินเวลาหมดอายุอีก RESEND_GRACE_MS (ใช้ยืนยัน OTP ไม่ได้ ใช้เป็นหลักฐานขอรอบใหม่เท่านั้น)

  ข้อจำกัด: state อยู่ในหน่วยความจำ ใช้ได้กับการรัน instance เดียว (ตามที่ docker-compose.yml เป็นอยู่)
  และ restart เซิร์ฟเวอร์ทำให้ OTP ที่ค้างอยู่ใช้ไม่ได้ ผู้ใช้ต้องขอรหัสใหม่
*/

export type OtpPurpose = "login" | "general";

/// จำนวนครั้งที่เดาผิดได้ต่อ OTP หนึ่งรอบ
export const MAX_ATTEMPTS = 5;

/// ขอ OTP ได้ไม่เกิน MAX_ISSUES_PER_WINDOW ครั้งต่ออีเมลต่อประเภทใน ISSUE_WINDOW_MS
/// นับแยกประเภท เพื่อไม่ให้ใครก็ตามที่ขอ OTP (general) ของอีเมลเหยื่อรัว ๆ ไปบล็อกการล็อกอินของเหยื่อ
const MAX_ISSUES_PER_WINDOW = 5;
const ISSUE_WINDOW_MS = 15 * 60 * 1000;

/// challenge ประเภท login ถูกเก็บไว้เกินเวลาหมดอายุเท่านี้ เพื่อใช้เป็นหลักฐานว่าผ่านรหัสผ่านมาแล้วตอนกด Resend
const RESEND_GRACE_MS = 10 * 60 * 1000;

/// กด Resend ต่อเนื่องได้ไม่เกินเท่านี้นับจากตอนผ่านรหัสผ่านครั้งแรก หลังจากนั้นต้องกรอกรหัสผ่านใหม่
const LOGIN_SESSION_MAX_MS = 15 * 60 * 1000;

/// เพดานจำนวน challenge ที่ค้างในหน่วยความจำ กัน memory โตไม่จำกัด
const MAX_CHALLENGES = 50_000;

const MIN_SECRET_LENGTH = 32;
const REF_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // ตัดตัวที่สับสนง่าย: 0 O 1 I
const REF_LENGTH = 6;

interface Challenge {
  ref: string;
  email: string;
  purpose: OtpPurpose;
  digest: Buffer; // HMAC ของ OTP ไม่เก็บ OTP ตรง ๆ
  expires: number;
  attempts: number;
  authAt: number; // เวลาที่ผ่านรหัสผ่าน (ใช้กับ login) สืบทอดไปยังรอบที่ขอผ่าน Resend เพื่อจำกัดอายุรวม
}

export class OtpRateLimitError extends Error {
  retryAfterSeconds: number;
  constructor(retryAfterSeconds: number) {
    super("ขอรหัส OTP บ่อยเกินไป กรุณาลองใหม่ภายหลัง");
    this.name = "OtpRateLimitError";
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

/// ขอ OTP ใหม่ผ่าน Resend ไม่ได้ (ไม่มี/หมดช่วง/อีเมลไม่ตรง) ต้องให้ผู้ใช้กรอกรหัสผ่านที่หน้า login ใหม่
export class OtpResendNotAllowedError extends Error {
  constructor() {
    super("เซสชันเข้าสู่ระบบหมดอายุ กรุณาเข้าสู่ระบบใหม่");
    this.name = "OtpResendNotAllowedError";
  }
}

export type VerifyResult =
  | { ok: true }
  | { ok: false; attemptsLeft?: number };

interface MailParams {
  email: string;
  otp: string;
  ref: string;
  expiresIn: number;
}

/* ---------- state ---------- */

const challenges = new Map<string, Challenge>(); // key = sha256(hash)
const activeByEmailPurpose = new Map<string, string>(); // `${purpose}:${email}` -> key
const recentIssues = new Map<string, number[]>(); // `${purpose}:${email lowercase}` -> เวลาที่ขอ OTP

let now = () => Date.now();
let mailer: (p: MailParams) => Promise<unknown> = sendOTPEmail;

/* ---------- config ---------- */

/// อ่านค่าตอนใช้งาน (ไม่อ่านตอน import) เพราะ dotenv ใน index.ts รันหลัง import
function getSecret(): string {
  const secret = process.env.OTP_SECRET;
  if (!secret || secret.length < MIN_SECRET_LENGTH) {
    throw new Error(
      `OTP_SECRET ต้องตั้งค่าและยาวอย่างน้อย ${MIN_SECRET_LENGTH} ตัวอักษร ` +
      `สร้างได้ด้วย: node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"`
    );
  }
  return secret;
}

function getExpireMinutes(): number {
  return Number(process.env.OTP_EXPIRE_MINUTES) || 1;
}

/// ทางผ่อนผันชั่วคราวระหว่างรอแอปรุ่นใหม่ (ที่ Resend ผ่าน /auth/login/resend_otp):
/// เปิดแล้ว /auth/login/verify_otp จะรับ OTP ประเภท general ด้วย ซึ่งเปิดช่องให้เดา OTP โดยไม่ต้องรู้รหัสผ่าน (ช้าลงแต่ยังเกิดได้)
/// ต้องปิด (เอาออกจาก .env) ทันทีที่แอปรุ่นใหม่ถูกใช้งานแล้ว
export function allowGeneralOtpAtLogin(): boolean {
  return process.env.OTP_ALLOW_GENERAL_AT_LOGIN === "true";
}

/// เรียกตอนเริ่มเซิร์ฟเวอร์ ถ้าไม่ได้ตั้ง OTP_SECRET ให้ล้มทันที ไม่ใช้ค่าเริ่มต้น
export function assertOtpConfig(): void {
  getSecret();
  if (allowGeneralOtpAtLogin()) {
    console.warn(
      "[OTP] OTP_ALLOW_GENERAL_AT_LOGIN=true: /auth/login/verify_otp รับ OTP จาก /auth/signup/send_otp ด้วย " +
      "ใช้ชั่วคราวระหว่างอัปเดตแอปเท่านั้น แล้วเอาค่านี้ออกจาก .env"
    );
  }
}

/* ---------- helpers ---------- */

function storeKey(hash: string): string {
  return crypto.createHash("sha256").update(hash).digest("hex");
}

function computeDigest(secret: string, ref: string, email: string, otp: string, expires: number): Buffer {
  return crypto.createHmac("sha256", secret).update(`${ref}.${email}.${otp}.${expires}`).digest();
}

function generateRef(): string {
  let ref = "";
  for (let i = 0; i < REF_LENGTH; i++) {
    ref += REF_ALPHABET[crypto.randomInt(0, REF_ALPHABET.length)];
  }
  return ref;
}

function removeChallenge(key: string, challenge: Challenge): void {
  challenges.delete(key);
  const activeKey = `${challenge.purpose}:${challenge.email}`;
  if (activeByEmailPurpose.get(activeKey) === key) {
    activeByEmailPurpose.delete(activeKey);
  }
}

function purgeExpired(): void {
  const t = now();
  for (const [key, ch] of challenges) {
    const keepUntil = ch.expires + (ch.purpose === "login" ? RESEND_GRACE_MS : 0);
    if (keepUntil < t) removeChallenge(key, ch);
  }
  for (const [email, times] of recentIssues) {
    const live = times.filter((ts) => t - ts < ISSUE_WINDOW_MS);
    if (live.length === 0) recentIssues.delete(email);
    else recentIssues.set(email, live);
  }
}

/// จำกัดจำนวนครั้งที่ขอ OTP ต่ออีเมลต่อประเภท (นับทุกครั้งที่ขอ ไม่ว่าส่งสำเร็จหรือไม่)
function registerIssueOrThrow(purpose: OtpPurpose, email: string): void {
  const key = `${purpose}:${email.trim().toLowerCase()}`;
  const t = now();
  const times = (recentIssues.get(key) ?? []).filter((ts) => t - ts < ISSUE_WINDOW_MS);

  if (times.length >= MAX_ISSUES_PER_WINDOW) {
    const oldest = times[0] ?? t;
    const retryAfter = Math.max(1, Math.ceil((oldest + ISSUE_WINDOW_MS - t) / 1000));
    throw new OtpRateLimitError(retryAfter);
  }
  times.push(t);
  recentIssues.set(key, times);
}

const cleaner = setInterval(purgeExpired, 60_000);
cleaner.unref(); // ไม่ให้ timer นี้ค้าง process

/* ---------- public API ---------- */

/// ออก OTP รอบใหม่ แล้วส่งอีเมล คืน hash (ส่งให้แอปเหมือนเดิม) และ ref (รหัสอ้างอิง ใช้แสดงผล)
/// authAt ใช้ภายในโดย resendLoginOTP เท่านั้น (ส่งต่อเวลาที่ผ่านรหัสผ่านครั้งแรก)
export const sendOTP = async (
  { email, purpose, authAt }: { email: string; purpose: OtpPurpose; authAt?: number | undefined }
): Promise<{ hash: string; ref: string }> => {
  const secret = getSecret();

  registerIssueOrThrow(purpose, email);

  if (challenges.size >= MAX_CHALLENGES) {
    purgeExpired();
    if (challenges.size >= MAX_CHALLENGES) {
      throw new OtpRateLimitError(60);
    }
  }

  const otp = otpGenerator.generate(6, {
    digits: true,
    lowerCaseAlphabets: false,
    upperCaseAlphabets: false,
    specialChars: false,
  });
  const ref = generateRef();
  const expireMinutes = getExpireMinutes();
  const expires = now() + expireMinutes * 60 * 1000;

  const digest = computeDigest(secret, ref, email, otp, expires);
  const hash = `${digest.toString("hex")}.${expires}`;

  try {
    await mailer({ email, otp, ref, expiresIn: expireMinutes });
  } catch (error) {
    // ไม่ log OTP หรืออีเมลผู้รับ
    console.error("[EMAIL ERROR] ส่งเมลไม่สำเร็จ:", error instanceof Error ? error.message : error);
    throw new Error("ไม่สามารถส่งอีเมล OTP ได้ กรุณาตรวจสอบการตั้งค่า Server");
  }

  // ลงทะเบียนหลังส่งสำเร็จ และยกเลิกรอบเก่าของอีเมล+ประเภทเดียวกัน (เหลือรอบล่าสุดรอบเดียว)
  const key = storeKey(hash);
  const activeKey = `${purpose}:${email}`;
  const previousKey = activeByEmailPurpose.get(activeKey);
  if (previousKey) {
    const previous = challenges.get(previousKey);
    if (previous) removeChallenge(previousKey, previous);
  }
  challenges.set(key, { ref, email, purpose, digest, expires, attempts: 0, authAt: authAt ?? now() });
  activeByEmailPurpose.set(activeKey, key);

  return { hash, ref };
};

/// ขอ OTP login รอบใหม่ (ปุ่ม Resend ของหน้า OTP login) โดยไม่ต้องกรอกรหัสผ่านซ้ำ
/// ต้องมี hash ของรอบ login เดิมของอีเมลเดียวกัน (ออกได้เฉพาะหลังผ่านรหัสผ่าน) และยังอยู่ในช่วงผ่อนผัน
/// ไม่ใช้ OTP จาก /signup/send_otp เป็นหลักฐาน เพราะใครก็ขอได้
export const resendLoginOTP = async (
  { email, hash }: { email: unknown; hash: unknown }
): Promise<{ hash: string; ref: string }> => {
  if (typeof email !== "string" || typeof hash !== "string") throw new OtpResendNotAllowedError();

  const previous = challenges.get(storeKey(hash));
  if (
    !previous ||
    previous.purpose !== "login" ||
    previous.email !== email ||
    now() > previous.expires + RESEND_GRACE_MS ||
    now() - previous.authAt > LOGIN_SESSION_MAX_MS
  ) {
    throw new OtpResendNotAllowedError();
  }

  return sendOTP({ email, purpose: "login", authAt: previous.authAt });
};

/// ตรวจ OTP ถูกต้อง = ใช้ได้ครั้งเดียว ผิด = นับจำนวนครั้ง ครบ MAX_ATTEMPTS = ยกเลิก OTP รอบนั้น
export const verifyOTP = (
  { email, otp, hash, purpose }: {
    email: unknown;
    otp: unknown;
    hash: unknown;
    purpose: OtpPurpose | readonly OtpPurpose[];
  }
): VerifyResult => {
  try {
    if (typeof email !== "string" || typeof otp !== "string" || typeof hash !== "string") {
      return { ok: false };
    }

    const key = storeKey(hash);
    const challenge = challenges.get(key);
    if (!challenge) return { ok: false };

    // หมดอายุแล้วใช้ไม่ได้ แต่ไม่ลบทันที: challenge login ต้องอยู่ต่อช่วงผ่อนผันเพื่อใช้ขอ Resend (ตัวล้างเป็นคนลบ)
    if (now() > challenge.expires) return { ok: false };

    // อีเมล/ประเภทไม่ตรง = ไม่ใช่ challenge ของคำขอนี้ ไม่นับเป็นการเดา และไม่เปิดเผยจำนวนครั้ง
    const allowedPurposes: readonly OtpPurpose[] = typeof purpose === "string" ? [purpose] : purpose;
    if (challenge.email !== email || !allowedPurposes.includes(challenge.purpose)) {
      return { ok: false };
    }

    const expected = computeDigest(getSecret(), challenge.ref, email, otp, challenge.expires);
    const matches =
      /^\d{6}$/.test(otp) &&
      expected.length === challenge.digest.length &&
      crypto.timingSafeEqual(expected, challenge.digest);

    if (matches) {
      removeChallenge(key, challenge); // ใช้ได้ครั้งเดียว
      return { ok: true };
    }

    challenge.attempts += 1;
    if (challenge.attempts >= MAX_ATTEMPTS) {
      removeChallenge(key, challenge);
      return { ok: false, attemptsLeft: 0 };
    }
    return { ok: false, attemptsLeft: MAX_ATTEMPTS - challenge.attempts };
  } catch {
    return { ok: false };
  }
};

/// สำหรับ unit test เท่านั้น
export const __testing = {
  setMailer(fn: (p: MailParams) => Promise<unknown>) { mailer = fn; },
  setNow(fn: () => number) { now = fn; },
  reset() {
    challenges.clear();
    activeByEmailPurpose.clear();
    recentIssues.clear();
    now = () => Date.now();
    mailer = sendOTPEmail;
  },
  size: () => challenges.size,
  purge: purgeExpired,
};
