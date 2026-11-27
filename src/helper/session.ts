import crypto from "crypto";
import { and, eq, isNotNull, lt, ne, or, sql } from "drizzle-orm";
import { db } from "../db/index.js";
import { userSessions } from "../db/schema.js";

/* ============================================================
   Session token (opaque) — แทน JWT
   อายุ session (ปรับที่ .env):
   - SESSION_IDLE_DAYS : ไม่ได้ใช้งานเกินกี่วันถึงหมดอายุ (จาก last_seen_at >> ใช้งานอยู่ = ต่ออายุอัตโนมัติ)
   - SESSION_MAX_DAYS  : อายุสูงสุดนับจากตอน login  (จาก created_at >> ต่อให้ใช้งานตลอดก็ต้อง login ใหม่)
============================================================ */

const DEFAULT_IDLE_DAYS = 7;
const DEFAULT_MAX_DAYS = 30;

// อ่านค่าจำนวนวันจาก .env (ไม่ถูกต้อง/ไม่ได้ตั้ง >> ใช้ค่าเริ่มต้น)
const readDays = (name: string, fallback: number): number => {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === "") return fallback;

  const n = Number(raw);
  if (Number.isInteger(n) && n > 0) return n;

  console.warn(`[session] ${name}="${raw}" ไม่ถูกต้อง โดยต้องเป็นจำนวนเต็มบวก ใช้ค่าเริ่มต้น ${fallback}`);
  return fallback;
};

export const SESSION_IDLE_DAYS = readDays("SESSION_IDLE_DAYS", DEFAULT_IDLE_DAYS);

// เพดานอายุต้องไม่สั้นกว่าเวลาที่ไม่ใช้งาน
const maxDaysRaw = readDays("SESSION_MAX_DAYS", DEFAULT_MAX_DAYS);
if (maxDaysRaw < SESSION_IDLE_DAYS) {
  console.warn(`[session] SESSION_MAX_DAYS (${maxDaysRaw}) น้อยกว่า SESSION_IDLE_DAYS (${SESSION_IDLE_DAYS}) ใช้ ${SESSION_IDLE_DAYS}`);
}
export const SESSION_MAX_DAYS = Math.max(maxDaysRaw, SESSION_IDLE_DAYS);

/// อัปเดต last_seen_at >> ทุก 5 นาที
export const SESSION_TOUCH_INTERVAL_MS = 5 * 60 * 1000;

/// รูปแบบ token
export const TOKEN_PREFIX = "nxs_";
export const TOKEN_MAX_LENGTH = 128;

/// วันหมดอายุสูงสุดของ session = วันที่ login + SESSION_MAX_DAYS (ส่งให้แอปแสดงแถบเตือนก่อนหมดรอบการใช้งาน)
export const sessionMaxExpiresAt = (createdAt: Date): Date =>
  new Date(createdAt.getTime() + SESSION_MAX_DAYS * 24 * 60 * 60 * 1000);

/// เงื่อนไข session ยังใช้ได้ (ใน middleware)
export const sessionIsActive = sql`(
  ${userSessions.revoked_at} IS NULL
  AND ${userSessions.last_seen_at} > now() - make_interval(days => ${SESSION_IDLE_DAYS})
  AND ${userSessions.created_at}   > now() - make_interval(days => ${SESSION_MAX_DAYS})
)`;

type Executor = Pick<typeof db, "update" | "insert">;

export const hashToken = (token: string): string =>
  crypto.createHash("sha256").update(token).digest("hex");

/// ── สร้าง session ใหม่ >> คืน token ตัวจริง ──
export async function createSession(userId: number, executor: Executor = db): Promise<string> {
  const token = TOKEN_PREFIX + crypto.randomBytes(32).toString("base64url");

  // created_at / last_seen_at ใช้ค่า now
  await executor.insert(userSessions).values({
    token_hash: hashToken(token),
    user_id: userId,
  });

  return token;
}

/// ── ต่ออายุ session >> วันหมดอายุจะเลื่อนตามคำนวณจาก last_seen_at ──
export async function touchSession(tokenHash: string): Promise<void> {
  await db
    .update(userSessions)
    .set({ last_seen_at: sql`now()` })
    .where(eq(userSessions.token_hash, tokenHash));
}

const notRevoked = sql`${userSessions.revoked_at} IS NULL`;

/// ── ออกจากระบบเครื่องนี้ (update เฉพาะ session ของ token นี้) ──
export async function revokeSession(tokenHash: string, executor: Executor = db): Promise<void> {
  await executor
    .update(userSessions)
    .set({ revoked_at: sql`now()` })
    .where(and(eq(userSessions.token_hash, tokenHash), notRevoked));
}

/// ── เพิกถอนทุกเครื่องของ user (ลืมรหัสผ่าน / ออกจากทุกเครื่อง) ──
export async function revokeAllSessions(userId: number, executor: Executor = db): Promise<void> {
  await executor
    .update(userSessions)
    .set({ revoked_at: sql`now()` })
    .where(and(eq(userSessions.user_id, userId), notRevoked));
}

/// ── เพิกถอนทุกเครื่อง "ยกเว้นเครื่องนี้" (เปลี่ยนรหัสผ่านตอน login อยู่) ──
export async function revokeOtherSessions(
  userId: number,
  keepTokenHash: string,
  executor: Executor = db
): Promise<void> {
  await executor
    .update(userSessions)
    .set({ revoked_at: sql`now()` })
    .where(
      and(
        eq(userSessions.user_id, userId),
        ne(userSessions.token_hash, keepTokenHash),
        notRevoked
      )
    );
}

/// ── ลบ session ที่หมดอายุนานแล้ว ──
export async function purgeExpiredSessions(): Promise<void> {
  await db
    .delete(userSessions)
    .where(
      or(
        lt(userSessions.last_seen_at, sql`now() - make_interval(days => ${SESSION_IDLE_DAYS})`),
        lt(userSessions.created_at, sql`now() - make_interval(days => ${SESSION_MAX_DAYS})`),
        and(isNotNull(userSessions.revoked_at), lt(userSessions.revoked_at, sql`now() - interval '1 day'`))
      )
    );
}
