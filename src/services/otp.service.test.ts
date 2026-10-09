import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  sendOTP,
  verifyOTP,
  resendLoginOTP,
  assertOtpConfig,
  allowGeneralOtpAtLogin,
  OtpRateLimitError,
  OtpResendNotAllowedError,
  MAX_ATTEMPTS,
  __testing,
} from "./otp.service.js";

const SECRET = "test-secret-".padEnd(48, "x");
const EMAIL = "user@example.com";

interface Sent { email: string; otp: string; ref: string; expiresIn: number }
let sent: Sent[] = [];
const lastMail = (): Sent => {
  const m = sent[sent.length - 1];
  assert.ok(m, "ยังไม่มีอีเมลที่ถูกส่ง");
  return m;
};

/// ออก OTP แล้วคืนค่าที่ผู้ใช้จะเห็น (hash/ref จาก response, otp จากอีเมล)
async function issue(purpose: "login" | "general", email = EMAIL) {
  const { hash, ref } = await sendOTP({ email, purpose });
  return { hash, ref, otp: lastMail().otp };
}

/// หา OTP ที่ผิดแน่นอน
const wrongOtp = (otp: string) => (otp === "000000" ? "000001" : "000000");

beforeEach(() => {
  __testing.reset();
  sent = [];
  process.env.OTP_SECRET = SECRET;
  delete process.env.OTP_EXPIRE_MINUTES;
  __testing.setMailer(async (p) => { sent.push(p); });
});

test("assertOtpConfig: ไม่มี OTP_SECRET หรือสั้นเกินไป ต้อง throw", () => {
  delete process.env.OTP_SECRET;
  assert.throws(() => assertOtpConfig(), /OTP_SECRET/);

  process.env.OTP_SECRET = "default_secret";
  assert.throws(() => assertOtpConfig(), /OTP_SECRET/);

  process.env.OTP_SECRET = SECRET;
  assert.doesNotThrow(() => assertOtpConfig());
});

test("sendOTP: ไม่มี OTP_SECRET ต้องไม่ออก OTP (ไม่ fallback เป็นค่าเริ่มต้น)", async () => {
  delete process.env.OTP_SECRET;
  await assert.rejects(() => sendOTP({ email: EMAIL, purpose: "login" }), /OTP_SECRET/);
  assert.equal(sent.length, 0);
});

test("sendOTP: hash รูปแบบเดิม, ref 6 ตัว และ ref ในอีเมลตรงกับที่คืนให้แอป", async () => {
  const { hash, ref } = await sendOTP({ email: EMAIL, purpose: "login" });
  assert.match(hash, /^[0-9a-f]{64}\.\d+$/);
  assert.match(ref, /^[A-HJ-NP-Z2-9]{6}$/);
  assert.equal(lastMail().ref, ref);
  assert.match(lastMail().otp, /^\d{6}$/);
});

test("verifyOTP: OTP ถูกต้องใช้ได้ครั้งเดียว", async () => {
  const { hash, otp } = await issue("login");
  assert.deepEqual(verifyOTP({ email: EMAIL, otp, hash, purpose: "login" }), { ok: true });
  assert.deepEqual(verifyOTP({ email: EMAIL, otp, hash, purpose: "login" }), { ok: false });
});

test("verifyOTP: hash ที่ปลอมด้วย secret เริ่มต้นเดิม (default_secret) ต้องถูกปฏิเสธ", () => {
  const expires = Date.now() + 3_600_000;
  const otp = "000000";
  const forged =
    crypto.createHmac("sha256", "default_secret").update(`${EMAIL}.${otp}.${expires}`).digest("hex") +
    `.${expires}`;
  for (const purpose of ["login", "general"] as const) {
    assert.deepEqual(verifyOTP({ email: EMAIL, otp, hash: forged, purpose }), { ok: false });
  }
});

test("verifyOTP: hash ที่ปลอมด้วย secret จริงแต่ไม่มี challenge ในระบบ ต้องถูกปฏิเสธ", () => {
  const expires = Date.now() + 3_600_000;
  const otp = "123456";
  const forged =
    crypto.createHmac("sha256", SECRET).update(`${EMAIL}.${otp}.${expires}`).digest("hex") + `.${expires}`;
  assert.deepEqual(verifyOTP({ email: EMAIL, otp, hash: forged, purpose: "login" }), { ok: false });
});

test("verifyOTP: เดาผิดนับจำนวนครั้งที่เหลือ และครบ 5 ครั้งแล้ว OTP รอบนั้นใช้ไม่ได้อีก แม้เดาถูก", async () => {
  const { hash, otp } = await issue("login");
  const bad = wrongOtp(otp);

  for (let i = 1; i <= MAX_ATTEMPTS; i++) {
    const r = verifyOTP({ email: EMAIL, otp: bad, hash, purpose: "login" });
    assert.deepEqual(r, { ok: false, attemptsLeft: MAX_ATTEMPTS - i });
  }

  // OTP ถูกต้องแต่หลัง challenge ถูกยกเลิกแล้ว
  assert.deepEqual(verifyOTP({ email: EMAIL, otp, hash, purpose: "login" }), { ok: false });
});

test("verifyOTP: เดาผิด 4 ครั้งแล้วเดาถูกครั้งที่ 5 ยังผ่าน", async () => {
  const { hash, otp } = await issue("login");
  for (let i = 0; i < MAX_ATTEMPTS - 1; i++) {
    verifyOTP({ email: EMAIL, otp: wrongOtp(otp), hash, purpose: "login" });
  }
  assert.deepEqual(verifyOTP({ email: EMAIL, otp, hash, purpose: "login" }), { ok: true });
});

test("verifyOTP: รูปแบบ OTP ผิด (ไม่ใช่เลข 6 หลัก) ถูกปฏิเสธและนับเป็นการเดา", async () => {
  const { hash } = await issue("login");
  assert.deepEqual(verifyOTP({ email: EMAIL, otp: "12345", hash, purpose: "login" }), { ok: false, attemptsLeft: 4 });
  assert.deepEqual(verifyOTP({ email: EMAIL, otp: "abcdef", hash, purpose: "login" }), { ok: false, attemptsLeft: 3 });
});

test("verifyOTP: OTP จาก send_otp (general) เอาไปใช้ที่ login ไม่ได้ และไม่ถูกนับ/ไม่ถูกใช้หมด", async () => {
  const { hash, otp } = await issue("general");

  // ผู้โจมตีลองเดาที่ login ซ้ำ ๆ ต้องไม่ผ่านและไม่ได้รู้จำนวนครั้ง
  for (let i = 0; i < 20; i++) {
    assert.deepEqual(verifyOTP({ email: EMAIL, otp, hash, purpose: "login" }), { ok: false });
  }
  // แม้ OTP ถูกต้องก็ผ่านที่ login ไม่ได้
  assert.deepEqual(verifyOTP({ email: EMAIL, otp, hash, purpose: "login" }), { ok: false });

  // แต่เจ้าของ OTP ยังใช้ได้ถูกที่ (สมัคร/รีเซ็ตรหัสผ่าน)
  assert.deepEqual(verifyOTP({ email: EMAIL, otp, hash, purpose: "general" }), { ok: true });
});

test("verifyOTP: OTP จาก login เอาไปใช้ที่ general ไม่ได้", async () => {
  const { hash, otp } = await issue("login");
  assert.deepEqual(verifyOTP({ email: EMAIL, otp, hash, purpose: "general" }), { ok: false });
});

test("verifyOTP: อีเมลไม่ตรงกับ challenge ถูกปฏิเสธโดยไม่นับเป็นการเดา", async () => {
  const { hash, otp } = await issue("login");
  assert.deepEqual(verifyOTP({ email: "other@example.com", otp, hash, purpose: "login" }), { ok: false });
  assert.deepEqual(verifyOTP({ email: EMAIL, otp, hash, purpose: "login" }), { ok: true });
});

test("sendOTP: ขอรอบใหม่ของอีเมล+ประเภทเดียวกัน รอบเก่าต้องใช้ไม่ได้", async () => {
  const first = await issue("login");
  const second = await issue("login");
  assert.notEqual(first.ref, second.ref);

  assert.deepEqual(verifyOTP({ email: EMAIL, otp: first.otp, hash: first.hash, purpose: "login" }), { ok: false });
  assert.deepEqual(verifyOTP({ email: EMAIL, otp: second.otp, hash: second.hash, purpose: "login" }), { ok: true });
});

test("sendOTP: รอบของประเภทต่างกันไม่ล้มกัน", async () => {
  const general = await issue("general");
  const login = await issue("login");
  assert.deepEqual(verifyOTP({ email: EMAIL, otp: general.otp, hash: general.hash, purpose: "general" }), { ok: true });
  assert.deepEqual(verifyOTP({ email: EMAIL, otp: login.otp, hash: login.hash, purpose: "login" }), { ok: true });
});

test("verifyOTP: หมดอายุแล้วใช้ไม่ได้ (1 นาทีโดยค่าเริ่มต้น)", async () => {
  let t = 1_000_000;
  __testing.setNow(() => t);
  const { hash, otp } = await issue("login");

  t += 60_000; // ครบ 1 นาทีพอดี ยังใช้ได้
  const ok = verifyOTP({ email: EMAIL, otp, hash, purpose: "login" });
  assert.deepEqual(ok, { ok: true });

  const again = await issue("login", "b@example.com");
  t += 60_001; // เกิน 1 นาที
  assert.deepEqual(verifyOTP({ email: "b@example.com", otp: again.otp, hash: again.hash, purpose: "login" }), { ok: false });
});

test("sendOTP: ขอ OTP เกิน 5 ครั้งใน 15 นาทีต่ออีเมลต่อประเภท ต้องถูกจำกัด (ไม่สนตัวพิมพ์เล็กใหญ่) และกลับมาขอได้หลังพ้นช่วงเวลา", async () => {
  let t = 5_000_000;
  __testing.setNow(() => t);

  const variants = [EMAIL, "USER@example.com", EMAIL, "User@Example.com", EMAIL];
  for (const e of variants) await sendOTP({ email: e, purpose: "general" });
  assert.equal(sent.length, 5);

  await assert.rejects(
    () => sendOTP({ email: "uSeR@example.com", purpose: "general" }),
    (err: unknown) => err instanceof OtpRateLimitError && err.retryAfterSeconds > 0
  );
  assert.equal(sent.length, 5, "ต้องไม่ส่งอีเมลเพิ่มเมื่อถูกจำกัด");

  // อีเมลอื่นไม่ถูกกระทบ
  await sendOTP({ email: "someone@example.com", purpose: "general" });

  t += 15 * 60 * 1000 + 1;
  await assert.doesNotReject(() => sendOTP({ email: EMAIL, purpose: "general" }));
});

test("sendOTP: ใครขอ OTP (general) ของอีเมลเหยื่อรัว ๆ ต้องไม่บล็อกการออก OTP login ของเหยื่อ", async () => {
  for (let i = 0; i < 5; i++) await sendOTP({ email: EMAIL, purpose: "general" });
  await assert.rejects(() => sendOTP({ email: EMAIL, purpose: "general" }), OtpRateLimitError);

  const login = await issue("login"); // ผู้ใช้จริงที่ผ่านรหัสผ่านแล้วต้องยังได้ OTP
  assert.deepEqual(verifyOTP({ email: EMAIL, otp: login.otp, hash: login.hash, purpose: "login" }), { ok: true });
});

test("sendOTP: ส่งอีเมลล้มเหลวต้อง throw และไม่ทิ้ง challenge ค้าง", async () => {
  __testing.setMailer(async () => { throw new Error("smtp down"); });
  const silenced = console.error;
  console.error = () => {};
  try {
    await assert.rejects(() => sendOTP({ email: EMAIL, purpose: "login" }), /ไม่สามารถส่งอีเมล OTP/);
  } finally {
    console.error = silenced;
  }
  assert.equal(__testing.size(), 0);
});

test("verifyOTP: อินพุตที่ไม่ใช่ string ต้องไม่ throw และไม่ผ่าน", async () => {
  const { hash, otp } = await issue("login");
  const bad: unknown[] = [undefined, null, 123, {}, [], true];
  for (const v of bad) {
    assert.deepEqual(verifyOTP({ email: v, otp, hash, purpose: "login" }), { ok: false });
    assert.deepEqual(verifyOTP({ email: EMAIL, otp: v, hash, purpose: "login" }), { ok: false });
    assert.deepEqual(verifyOTP({ email: EMAIL, otp, hash: v, purpose: "login" }), { ok: false });
  }
  // ยังไม่ถูกใช้หมดไปจากอินพุตผิดรูปแบบ
  assert.deepEqual(verifyOTP({ email: EMAIL, otp, hash, purpose: "login" }), { ok: true });
});

test("ไม่มี OTP หรืออีเมลถูกพิมพ์ลง log ระหว่างออกและตรวจ OTP", async () => {
  const lines: string[] = [];
  const originals = {
    log: console.log, info: console.info, warn: console.warn, error: console.error, debug: console.debug,
  };
  const capture = (...args: unknown[]) => { lines.push(args.map(String).join(" ")); };
  console.log = capture; console.info = capture; console.warn = capture; console.error = capture; console.debug = capture;

  let otp = "";
  try {
    const issued = await issue("login");
    otp = issued.otp;
    verifyOTP({ email: EMAIL, otp: wrongOtp(otp), hash: issued.hash, purpose: "login" });
    verifyOTP({ email: EMAIL, otp, hash: issued.hash, purpose: "login" });
  } finally {
    Object.assign(console, originals);
  }

  const output = lines.join("\n");
  assert.ok(!output.includes(otp), "OTP รั่วใน log");
  assert.ok(!output.includes(EMAIL), "อีเมลรั่วใน log");
});


/* ---------- Resend ของหน้า OTP login ---------- */

test("resendLoginOTP: ขอรอบใหม่ได้ด้วย hash ของรอบ login เดิม รอบเก่าใช้ไม่ได้ และรอบใหม่ยืนยันได้", async () => {
  const first = await issue("login");
  const resent = await resendLoginOTP({ email: EMAIL, hash: first.hash });
  const otp2 = lastMail().otp;

  assert.notEqual(resent.hash, first.hash);
  assert.notEqual(resent.ref, first.ref);
  assert.equal(lastMail().ref, resent.ref, "ref ในอีเมลต้องตรงกับที่คืนให้แอป");

  assert.deepEqual(verifyOTP({ email: EMAIL, otp: first.otp, hash: first.hash, purpose: "login" }), { ok: false });
  assert.deepEqual(verifyOTP({ email: EMAIL, otp: otp2, hash: resent.hash, purpose: "login" }), { ok: true });
});

test("resendLoginOTP: กดหลัง OTP เดิมหมดอายุได้ภายใน 10 นาที แต่ OTP เดิมยืนยันไม่ได้ พ้นช่วงนั้นต้องล็อกอินใหม่", async () => {
  let t = 10_000_000;
  __testing.setNow(() => t);

  const a = await issue("login");
  t += 61_000; // OTP หมดอายุ (1 นาที)
  assert.deepEqual(verifyOTP({ email: EMAIL, otp: a.otp, hash: a.hash, purpose: "login" }), { ok: false });
  await assert.doesNotReject(() => resendLoginOTP({ email: EMAIL, hash: a.hash }));

  const b = await issue("login", "b@example.com");
  t += 60_000 + 10 * 60_000 + 1; // พ้นเวลาหมดอายุ + ช่วงผ่อนผัน
  await assert.rejects(() => resendLoginOTP({ email: "b@example.com", hash: b.hash }), OtpResendNotAllowedError);
});

test("resendLoginOTP: ไม่รับ hash จาก general, อีเมลไม่ตรง, hash ที่ไม่รู้จัก หรืออินพุตที่ไม่ใช่ string และต้องไม่ส่งอีเมล", async () => {
  const general = await issue("general");
  const login = await issue("login");
  const mailsBefore = sent.length;

  // OTP จาก send_otp ใครก็ขอได้ จึงห้ามใช้เป็นหลักฐานว่าผ่านรหัสผ่านแล้ว
  await assert.rejects(() => resendLoginOTP({ email: EMAIL, hash: general.hash }), OtpResendNotAllowedError);
  await assert.rejects(() => resendLoginOTP({ email: "other@example.com", hash: login.hash }), OtpResendNotAllowedError);
  await assert.rejects(() => resendLoginOTP({ email: EMAIL, hash: `${"0".repeat(64)}.123` }), OtpResendNotAllowedError);
  for (const v of [undefined, null, 123, {}, []] as unknown[]) {
    await assert.rejects(() => resendLoginOTP({ email: v, hash: login.hash }), OtpResendNotAllowedError);
    await assert.rejects(() => resendLoginOTP({ email: EMAIL, hash: v }), OtpResendNotAllowedError);
  }
  assert.equal(sent.length, mailsBefore);
});

test("resendLoginOTP: กด Resend ต่อเนื่องได้ไม่เกิน 15 นาทีนับจากผ่านรหัสผ่านครั้งแรก", async () => {
  let t = 20_000_000;
  __testing.setNow(() => t);

  const first = await issue("login");
  t += 9 * 60_000;
  const second = await resendLoginOTP({ email: EMAIL, hash: first.hash }); // รวม 9 นาที ผ่าน
  t += 9 * 60_000; // รวม 18 นาที
  await assert.rejects(() => resendLoginOTP({ email: EMAIL, hash: second.hash }), OtpResendNotAllowedError);
});

test("resendLoginOTP: นับรวมในขีดจำกัดการขอ OTP login ต่ออีเมล (5 ครั้งต่อ 15 นาที)", async () => {
  let cur = (await issue("login")).hash; // ครั้งที่ 1
  for (let i = 0; i < 4; i++) cur = (await resendLoginOTP({ email: EMAIL, hash: cur })).hash; // ครั้งที่ 2-5
  await assert.rejects(() => resendLoginOTP({ email: EMAIL, hash: cur }), OtpRateLimitError);
});

test("resendLoginOTP: รอบ login ที่ถูกล็อกเพราะเดาผิดครบกำหนดแล้ว ใช้เป็นหลักฐานขอ Resend ไม่ได้", async () => {
  const { hash, otp } = await issue("login");
  for (let i = 0; i < MAX_ATTEMPTS; i++) {
    verifyOTP({ email: EMAIL, otp: wrongOtp(otp), hash, purpose: "login" });
  }
  await assert.rejects(() => resendLoginOTP({ email: EMAIL, hash }), OtpResendNotAllowedError);
});

/* ---------- ทางผ่อนผัน OTP_ALLOW_GENERAL_AT_LOGIN และตัวล้าง ---------- */

test("verifyOTP: purpose เป็น array (ทางผ่อนผัน) รับได้ทั้ง general และ login แต่ยังนับจำนวนครั้งและใช้ได้ครั้งเดียวเหมือนเดิม", async () => {
  const general = await issue("general");
  const purposes = ["login", "general"] as const;

  assert.deepEqual(
    verifyOTP({ email: EMAIL, otp: wrongOtp(general.otp), hash: general.hash, purpose: purposes }),
    { ok: false, attemptsLeft: MAX_ATTEMPTS - 1 }
  );
  assert.deepEqual(verifyOTP({ email: EMAIL, otp: general.otp, hash: general.hash, purpose: purposes }), { ok: true });
  assert.deepEqual(verifyOTP({ email: EMAIL, otp: general.otp, hash: general.hash, purpose: purposes }), { ok: false });
});

test("allowGeneralOtpAtLogin: ปิดเป็นค่าเริ่มต้น เปิดเฉพาะเมื่อเป็น 'true' เท่านั้น และ assertOtpConfig เตือนเมื่อเปิด", () => {
  delete process.env.OTP_ALLOW_GENERAL_AT_LOGIN;
  assert.equal(allowGeneralOtpAtLogin(), false);
  for (const v of ["1", "yes", "TRUE", ""]) {
    process.env.OTP_ALLOW_GENERAL_AT_LOGIN = v;
    assert.equal(allowGeneralOtpAtLogin(), false, `ค่า ${JSON.stringify(v)} ต้องไม่เปิด`);
  }

  const warnings: string[] = [];
  const originalWarn = console.warn;
  console.warn = (...args: unknown[]) => { warnings.push(args.map(String).join(" ")); };
  try {
    delete process.env.OTP_ALLOW_GENERAL_AT_LOGIN;
    assertOtpConfig();
    assert.equal(warnings.length, 0);

    process.env.OTP_ALLOW_GENERAL_AT_LOGIN = "true";
    assert.equal(allowGeneralOtpAtLogin(), true);
    assertOtpConfig();
    assert.equal(warnings.length, 1);
    assert.match(warnings[0] ?? "", /OTP_ALLOW_GENERAL_AT_LOGIN/);
  } finally {
    console.warn = originalWarn;
    delete process.env.OTP_ALLOW_GENERAL_AT_LOGIN;
  }
});

test("ตัวล้าง: challenge general ถูกลบหลังหมดอายุ ส่วน login ถูกเก็บต่ออีก 10 นาทีแล้วจึงลบ", async () => {
  let t = 30_000_000;
  __testing.setNow(() => t);

  await issue("general");
  await issue("login", "b@example.com");
  assert.equal(__testing.size(), 2);

  t += 61_000; // ทั้งคู่หมดอายุ
  __testing.purge();
  assert.equal(__testing.size(), 1, "general ต้องถูกลบ login ต้องยังอยู่ (ช่วงผ่อนผัน)");

  t += 10 * 60_000;
  __testing.purge();
  assert.equal(__testing.size(), 0);
});
