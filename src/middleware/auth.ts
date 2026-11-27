import type { NextFunction, Request, Response } from "express";
import { and, eq } from "drizzle-orm";
import { db } from "../db/index.js";
import { users, userSessions } from "../db/schema.js";
import {
  hashToken,
  touchSession,
  sessionIsActive,
  sessionMaxExpiresAt,
  TOKEN_PREFIX,
  TOKEN_MAX_LENGTH,
  SESSION_TOUCH_INTERVAL_MS,
} from "../helper/session.js";

// AuthRequest Interface
export interface AuthRequest extends Request {
  user?: number; // id ของ user
  token?: string; // session token (ค่าจริง)
  sessionHash?: string; // SHA-256 ของ token = รหัส session token
  sessionMaxExpiresAt?: Date; // วันหมดอายุสูงสุดของ session นี้
}

export const auth = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  try {
    
    // ดึง token จาก header
    const token = req.header("x-auth-token");

        // ถ้าไม่มี token → ตัดทิ้งทันที
        if (!token) {
          res.status(401).json({ error: "ไม่พบ token หรือการเข้าถึงถูกปฏิเสธ" });
          return;
        }

    // รูปแบบ token ผิด
    if (!token.startsWith(TOKEN_PREFIX) || token.length > TOKEN_MAX_LENGTH) {
      res.status(401).json({ error: "Token ไม่ถูกต้องหรือหมดอายุ" });
      return;
    }

    // ค้น session จาก hash ของ token
    const tokenHash = hashToken(token);
    const [session] = await db
      .select({
        user_id: userSessions.user_id,
        last_seen_at: userSessions.last_seen_at,
        created_at: userSessions.created_at,
      })
      .from(userSessions)
      .innerJoin(users, eq(users.id, userSessions.user_id)) // user ถูกลบ >> ไม่มี session ที่ใช้ได้
      .where(
        and(
          eq(userSessions.token_hash, tokenHash),
          sessionIsActive
        )
      )
      .limit(1);

    // ไม่พบ / ถูกเพิกถอน / หมดอายุ 
    if (!session) {
      res.status(401).json({ error: "Token ไม่ถูกต้อง หมดอายุ หรือถูกเพิกถอนจากระบบแล้ว กรุณาเข้าสู่ระบบใหม่อีกครั้ง" });
      return;
    }

    // ต่ออายุแบบ sliding: บันทึกว่าเพิ่งใช้งาน
    if (Date.now() - session.last_seen_at.getTime() > SESSION_TOUCH_INTERVAL_MS) {
      touchSession(tokenHash).catch((e) => console.error("[auth] touchSession error:", e));
    }

    // แนบข้อมูล user ลง req >> route ใช้ req.user (id ของ user ที่ login แล้ว)
    req.user = session.user_id;
    req.token = token;
    req.sessionHash = tokenHash;
    req.sessionMaxExpiresAt = sessionMaxExpiresAt(session.created_at);
    next();
  } catch (e) {
    // error ที่ไม่คาดคิด >> ต้องไม่ตอบ 401 (เพราะ 401 แอปจะเข้าใจว่า session ถูกเพิกถอน)
    console.error("[auth] middleware error:", e);
    res.status(500).json({ error: "ตรวจสอบสิทธิ์ไม่สำเร็จ กรุณาลองใหม่อีกครั้ง" });
  }
};

/// ── ตรวจสอบสถานะว่าต้องเป็น admin เท่านั้น ────────────────────────────
export const requireAdmin = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  try {
    const [u] = await db
      .select({ status: users.status })
      .from(users)
      .where(eq(users.id, req.user!));

    if (u?.status !== "admin") {
      res.status(403).json({ error: "เฉพาะผู้ดูแลระบบเท่านั้น" });
      return;
    }
    next();
  } catch (e) {
    res.status(500).json({ error: "ตรวจสอบสิทธิ์ไม่สำเร็จ" });
  }
};