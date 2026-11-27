import express from "express";
import { faultRouter, faultInjector }  from "./middleware/fault.js"
import { purgeOldOtpChallenges } from "./services/otp.service.js";
import authRouter from "./routes/auth.js";
import taskRouter from "./routes/task.js"
import point_task_Router from "./routes/point_task.js"

import dotenv from "dotenv";
dotenv.config();

import { startPurgeJob } from "./services/purge.service.js";
import { purgeExpiredSessions, SESSION_IDLE_DAYS, SESSION_MAX_DAYS } from "./helper/session.js";
startPurgeJob();


const app = express();

app.use(express.json());

// เครื่องมือจำลอง error สำหรับทดสอบ sync >> เปิดเฉพาะเมื่อตั้ง ENABLE_FAULT_INJECTION=true เอง
if (process.env.ENABLE_FAULT_INJECTION === "true") {
  console.warn("[WARN] Fault injection ENABLED — ห้ามเปิดบน production");
  app.use(faultRouter);
  app.use(faultInjector);
}


app.use("/auth" , authRouter);
app.use("/tasks" , taskRouter);
app.use("/point_tasks" , point_task_Router);

//app.use('/uploads', express.static('uploads'));
app.use("/points", point_task_Router);

app.get("/", (req, res) => {
    res.send("Welcome to my BUS 12")
})

app.use((req, res) => {
  res.status(404).json({ message: "Route not found on server" });
});

app.listen(3000, "0.0.0.0",() => {
  console.log('Server started on port 3000');

  // ลบ OTP ที่หมดอายุเกิน 1 วัน ทุก 6 ชั่วโมง
  setInterval(() => purgeOldOtpChallenges().catch(console.error), 6 * 60 * 60 * 1000);

  // ลบ session ที่หมดอายุ / ถูกเพิกถอนแล้ว ทุก 6 ชั่วโมง
  purgeExpiredSessions().catch(console.error);
  setInterval(() => purgeExpiredSessions().catch(console.error), 6 * 60 * 60 * 1000);
});