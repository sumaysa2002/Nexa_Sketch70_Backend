import type { Request, Response } from "express";
import { rateLimit, ipKeyGenerator } from "express-rate-limit";

/*
  Rate limit ของ endpoint ยืนยันตัวตน

  หมายเหตุ: ค่าจำกัดต่อ IP ตั้งไว้สูงโดยตั้งใจ เพราะผู้ใช้หลายคนอาจใช้ IP เดียวกัน (เช่น Wi-Fi สำนักงาน)
  ตัวป้องกันหลักอยู่ที่ต่ออีเมล (otp.service.ts จำกัดการขอ OTP, loginFailureLimiter จำกัด login ที่ล้มเหลว)
  และต่อ OTP หนึ่งรอบ (เดาผิดได้ 5 ครั้ง)

  ถ้ารันหลัง reverse proxy / ngrok ต้องตั้ง TRUST_PROXY ใน .env (ดู index.ts)
  ไม่เช่นนั้นทุกคำขอจะถูกนับเป็น IP ของ proxy
*/

const WINDOW_MS = 15 * 60 * 1000;
const MESSAGE = "ส่งคำขอบ่อยเกินไป กรุณาลองใหม่ภายหลัง";

// route ฝั่งนี้ตอบ error คนละ key (`message` / `error`) จึงส่งทั้งสองให้แอปอ่านได้ไม่ว่าจะ key ไหน
const handler = (_req: Request, res: Response) => {
  res.status(429).json({ message: MESSAGE, error: MESSAGE });
};

const common = {
  windowMs: WINDOW_MS,
  standardHeaders: "draft-7" as const,
  legacyHeaders: false,
  handler,
};

/// ทุก endpoint ยืนยันตัวตนที่ผูกกับ OTP ต่อ IP
export const authIpLimiter = rateLimit({ ...common, limit: 300 });

/// /auth/signup/send_otp ต่อ IP กันการส่งอีเมลไปยังหลายที่อยู่
export const sendOtpIpLimiter = rateLimit({ ...common, limit: 30 });

/// /auth/login นับเฉพาะครั้งที่ล้มเหลว ต่ออีเมล (ถ้าไม่มีอีเมลใน body ใช้ IP แทน)
export const loginFailureLimiter = rateLimit({
  ...common,
  limit: 10,
  skipSuccessfulRequests: true,
  keyGenerator: (req: Request) => {
    const email = (req.body as { email?: unknown } | undefined)?.email;
    if (typeof email === "string" && email.trim() !== "") {
      return `email:${email.trim().toLowerCase()}`;
    }
    return ipKeyGenerator(req.ip ?? "unknown");
  },
});
