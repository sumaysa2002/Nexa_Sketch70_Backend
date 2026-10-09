import { test, mock } from "node:test";
import assert from "node:assert/strict";

/*
  ตรวจเนื้อหาอีเมล OTP โดยจำลอง nodemailer (ไม่ส่งจริง)
  ต้องรันด้วย Node 22.3+ และ flag --experimental-test-module-mocks (ดู npm test)
*/

interface MailOptions { from: string; to: string; subject: string; html: string }
let captured: MailOptions | undefined;

mock.module("nodemailer", {
  defaultExport: {
    createTransport: () => ({
      sendMail: async (options: MailOptions) => { captured = options; return {}; },
    }),
  },
});

const { sendOTPEmail } = await import("./emailer.service.js");

test("sendOTPEmail: ใส่รหัสอ้างอิง (ref) ทั้งในหัวเรื่องและเนื้อหา พร้อม OTP และอายุรหัส", async () => {
  await sendOTPEmail({ email: "user@example.com", otp: "483920", ref: "K7M2QX", expiresIn: 1 });

  assert.ok(captured, "ต้องเรียก sendMail");
  assert.equal(captured.to, "user@example.com");
  assert.match(captured.subject, /\[Ref: K7M2QX\]$/);
  assert.ok(captured.html.includes("K7M2QX"), "เนื้อหาอีเมลต้องมี ref");
  assert.ok(captured.html.includes("483920"), "เนื้อหาอีเมลต้องมี OTP");
  assert.ok(captured.html.includes("1 นาที"), "เนื้อหาอีเมลต้องบอกอายุรหัส");
});

test("sendOTPEmail: OTP ไม่ปรากฏในหัวเรื่อง (หัวเรื่องเห็นได้จากหน้าจอล็อก/รายการอีเมล)", async () => {
  await sendOTPEmail({ email: "user@example.com", otp: "483920", ref: "K7M2QX", expiresIn: 1 });
  assert.ok(captured);
  assert.ok(!captured.subject.includes("483920"));
});
