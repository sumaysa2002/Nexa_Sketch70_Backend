//import type { UUID } from "crypto"; // ใช้เป็น type ของ user id (UUID จาก Postgres)
import type { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken"; // ใช้ verify JWT
import { db } from "../db/index.js"; // ตัวเชื่อม database (Drizzle)
import { users } from "../db/schema.js"; // ตาราง users
import { eq } from "drizzle-orm"; // helper ของ Drizzle สำหรับ WHERE

// AuthRequest Interface
export interface AuthRequest extends Request {
  user?: number; // id ของ user
  token?: string; // jwt token
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
          res.status(401).json({ error: "ไม่พบ token, การเข้าถึงถูกปฏิเสธ!" });
          return;
        }

    // ตรวจสอบ JWT (verify) >> ตรวจลายเซ็น, ตรวจว่า token ถูกสร้างด้วย secret เดียวกัน, ตรวจว่า token ไม่พัง / ไม่โดนแก้
    const verified = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET!);
    //const verified = jwt.verify(token, "passwordKey");

    // ถ้า token ผิด → throw error → เข้า catch
    if (!verified) {
      res.status(401).json({ error: "การตรวจสอบ Token ล้มเหลว!" });
      return;
    }

    // แปลง payload จาก token
    const verifiedToken = verified as { id: number };

    // ตรวจสอบ user ใน database
    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.id, verifiedToken.id));

        // ถ้าไม่มี user → access denied
        if (!user) {
        res.status(401).json({ error: "ไม่พบผู้ใช้งานในฐานข้อมูล" });
        return;
        }

    // แนบข้อมูล user ลง req >> จากนี้ route ถัดไปจะใช้ req.user (id ของ user ที่ login แล้ว)
    req.user = verifiedToken.id;
    req.token = token;
    next();
  } catch (e) {
    // ✅ เปลี่ยนจาก 500 → 401 เพราะ error ตรงนี้ส่วนใหญ่คือ token ผิด/หมดอายุ ไม่ใช่ server พัง
    res.status(401).json({ error: "Token ไม่ถูกต้องหรือหมดอายุ" });
    // res.status(500).json({ error: e });
  }
};
