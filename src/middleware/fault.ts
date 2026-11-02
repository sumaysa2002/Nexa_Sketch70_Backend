// ใช้เฉพาะตอนทดสอบ
import { Router, type Request, type Response, type NextFunction } from "express";

type Fault = { route: string; mode: "delay" | "status"; ms?: number; code?: number; times: number };
let fault: Fault | null = null;

export const faultRouter = Router();

faultRouter.post("/__fault", (req, res) => {
  const secret = process.env.FAULT_SECRET;
  if (!secret || req.get("x-fault-secret") !== secret) {
    return res.status(404).json({ message: "Route not found on server" });
  }
  fault = req.body?.route ? req.body : null;
  res.json({ fault });
});

export function faultInjector(req: Request, res: Response, next: NextFunction) {
  if (!fault || fault.times <= 0 || !req.path.includes(fault.route)) return next();
  fault.times--;

  if (fault.mode === "status") {
    const code = fault.code ?? 500;
    const reply = () => res.status(code).json({ error: `fault injection ${code}` });

    // body ถูกอ่านแล้ว (JSON) >> ตอบได้เลย
    // multipart ยังอัปโหลดอยู่ >> อ่านทิ้งให้หมดก่อน ไม่งั้น client จะเจอ connection reset แทน status
    if (req.readableEnded || (req as any)._body) return reply();
    req.on("end", reply);
    req.resume();
    return;
  }

  // delay: handler ทำงานและบันทึก DB จริง แต่หน่วง response >> จำลอง "server สร้างแล้วแต่ response หาย"
  const ms = fault.ms ?? 100_000;
  const json = res.json.bind(res);
  res.json = ((body: any) => { setTimeout(() => json(body), ms); return res; }) as any;
  next();
}