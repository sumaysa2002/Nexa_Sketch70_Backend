import { test, before, after, beforeEach, mock } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import express from "express";
import bcryptjs from "bcryptjs";

/*
  ทดสอบ router จริง (src/routes/auth.ts) ผ่าน HTTP โดยจำลองเฉพาะฐานข้อมูลกับการส่งอีเมล
  ต้องรันด้วย Node 22.3+ และ flag --experimental-test-module-mocks (ดู npm test)
*/

const SECRET = "route-test-secret-".padEnd(48, "x");
const PASSWORD = "correct horse battery";

interface FakeUser {
  id: number;
  email: string;
  password: string;
  first_name: string;
  status: string | null;
}

let rows: FakeUser[] = [];

// db จำลอง: where() คืนแถวที่ตั้งไว้ในแต่ละเทสต์ (แต่ละเทสต์มีผู้ใช้คนเดียว)
const tx = {
  update: () => ({ set: () => ({ where: () => ({ returning: async () => [{ id: 1 }] }) }) }),
  insert: () => ({ values: async () => undefined }),
};
const fakeDb = {
  select: () => ({ from: () => ({ where: async () => rows }) }),
  transaction: async (fn: (t: typeof tx) => Promise<unknown>) => fn(tx),
};

mock.module(new URL("../db/index.ts", import.meta.url).href, {
  namedExports: { db: fakeDb },
});

process.env.OTP_SECRET = SECRET;
process.env.ACCESS_TOKEN_SECRET = "access-secret-".padEnd(48, "y");

const { default: authRouter } = await import("./auth.js");
const { __testing } = await import("../services/otp.service.js");

interface Sent { email: string; otp: string; ref: string; expiresIn: number }
let sent: Sent[] = [];
const lastMail = (): Sent => {
  const m = sent[sent.length - 1];
  assert.ok(m, "ยังไม่มีอีเมลที่ถูกส่ง");
  return m;
};

let server: Server;
let base = "";
let counter = 0;
const newEmail = () => `route-user-${++counter}@example.com`;

async function post(path: string, body: unknown) {
  const res = await fetch(`${base}/auth${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let json: any = null;
  try { json = JSON.parse(text); } catch { /* ไม่ใช่ JSON */ }
  return { status: res.status, json, text, headers: res.headers };
}

function setUser(email: string): FakeUser {
  const user: FakeUser = {
    id: 7,
    email,
    password: bcryptjs.hashSync(PASSWORD, 4),
    first_name: "ทดสอบ",
    status: "user",
  };
  rows = [user];
  return user;
}

/// login ด้วยรหัสผ่านที่ถูกต้อง แล้วคืนค่าที่แอปได้รับ + OTP ที่อยู่ในอีเมล
async function loginOk(email: string) {
  setUser(email);
  const res = await post("/login", { email, password: PASSWORD });
  assert.equal(res.status, 200, res.text);
  return { hash: res.json.hash as string, ref: res.json.ref as string, otp: lastMail().otp, res };
}

/// ขอ OTP ผ่าน /signup/send_otp (ใครก็ขอได้ ไม่ต้องรู้รหัสผ่าน)
async function sendGeneralOtp(email: string) {
  const res = await post("/signup/send_otp", { email });
  assert.equal(res.status, 200, res.text);
  return { hash: res.json.hash as string, ref: res.json.ref as string, otp: lastMail().otp };
}

const wrongOtp = (otp: string) => (otp === "000000" ? "000001" : "000000");

before(async () => {
  const app = express();
  app.use(express.json());
  app.use("/auth", authRouter);
  await new Promise<void>((resolve) => { server = app.listen(0, "127.0.0.1", () => resolve()); });
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

beforeEach(() => {
  __testing.reset();
  sent = [];
  rows = [];
  process.env.OTP_SECRET = SECRET;
  delete process.env.OTP_ALLOW_GENERAL_AT_LOGIN;
  __testing.setMailer(async (p) => { sent.push(p); });
});

test("login → verify_otp: ได้ hash+ref ตรงกับอีเมล ไม่รั่ว OTP/รหัสผ่านใน response แล้วยืนยันได้ครั้งเดียว", async () => {
  const email = newEmail();
  const { hash, ref, otp, res } = await loginOk(email);

  assert.match(ref, /^[A-HJ-NP-Z2-9]{6}$/);
  assert.equal(lastMail().ref, ref, "ref ในอีเมลต้องตรงกับที่คืนให้แอป");
  assert.ok(!res.text.includes(otp), "response ของ /login ห้ามมี OTP");
  assert.equal(res.json.tempUser.password, undefined, "ห้ามส่ง password กลับ");

  const ok = await post("/login/verify_otp", { email, otp, hash });
  assert.equal(ok.status, 200, ok.text);
  assert.equal(typeof ok.json.token, "string");
  assert.equal(ok.json.password, undefined);

  const replay = await post("/login/verify_otp", { email, otp, hash });
  assert.equal(replay.status, 400, "OTP ต้องใช้ได้ครั้งเดียว");
});

test("login ด้วยรหัสผ่านผิด: ไม่ออก OTP และไม่ส่งอีเมล", async () => {
  const email = newEmail();
  setUser(email);
  const res = await post("/login", { email, password: "wrong" });
  assert.equal(res.status, 400);
  assert.equal(sent.length, 0);
});

test("verify_otp: เดาผิดได้ attempts_left ลดลง และครบ 5 ครั้งแล้วแม้เดาถูกก็ใช้ไม่ได้", async () => {
  const email = newEmail();
  const { hash, otp } = await loginOk(email);

  for (let i = 1; i <= 4; i++) {
    const r = await post("/login/verify_otp", { email, otp: wrongOtp(otp), hash });
    assert.equal(r.status, 400);
    assert.equal(r.json.attempts_left, 5 - i);
    assert.equal(typeof r.json.message, "string");
  }
  const fifth = await post("/login/verify_otp", { email, otp: wrongOtp(otp), hash });
  assert.equal(fifth.status, 400);
  assert.equal(fifth.json.attempts_left, 0);

  const correctButLocked = await post("/login/verify_otp", { email, otp, hash });
  assert.equal(correctButLocked.status, 400, "ล็อกแล้วต้องไม่ผ่านแม้ OTP ถูก");
  assert.equal(correctButLocked.json.token, undefined);
});

test("ช่องโหว่เดิม: hash ที่ปลอมด้วย default_secret ล็อกอินไม่ได้", async () => {
  const email = newEmail();
  setUser(email);
  const { createHmac } = await import("node:crypto");
  const expires = Date.now() + 3_600_000;
  const forged = `${createHmac("sha256", "default_secret").update(`${email}.000000.${expires}`).digest("hex")}.${expires}`;

  const r = await post("/login/verify_otp", { email, otp: "000000", hash: forged });
  assert.equal(r.status, 400);
  assert.equal(r.json.token, undefined);
});

test("ช่องโหว่เดิม: OTP ที่ขอผ่าน /signup/send_otp (ไม่ต้องรู้รหัสผ่าน) เอาไปล็อกอินไม่ได้", async () => {
  const email = newEmail();
  setUser(email);
  const { hash, otp } = await sendGeneralOtp(email);

  const r = await post("/login/verify_otp", { email, otp, hash });
  assert.equal(r.status, 400);
  assert.equal(r.json.token, undefined);
  assert.equal(r.json.attempts_left, undefined, "ไม่เปิดเผยจำนวนครั้งของ challenge ที่ไม่ใช่ประเภทนี้");

  // และยังใช้ถูกที่เดิมได้ (ไม่ถูกใช้หมดไปจากการลองผิดที่)
  setUser(email);
  const reset = await post("/login/reset_password/verify_and_reset", { email, otp, hash, new_password: "n3w-passw0rd!" });
  assert.equal(reset.status, 200, reset.text);
});

test("ทางผ่อนผัน OTP_ALLOW_GENERAL_AT_LOGIN=true: OTP จาก send_otp ใช้ที่ login ได้ (เพื่อแอปรุ่นเดิม) และปิดแล้วใช้ไม่ได้", async () => {
  const email = newEmail();
  setUser(email);

  const a = await sendGeneralOtp(email);
  process.env.OTP_ALLOW_GENERAL_AT_LOGIN = "true";
  const allowed = await post("/login/verify_otp", { email, otp: a.otp, hash: a.hash });
  assert.equal(allowed.status, 200, allowed.text);

  delete process.env.OTP_ALLOW_GENERAL_AT_LOGIN;
  const b = await sendGeneralOtp(email);
  const denied = await post("/login/verify_otp", { email, otp: b.otp, hash: b.hash });
  assert.equal(denied.status, 400);
});

test("Resend ของหน้า login: /login/resend_otp ออกรอบใหม่ รอบเก่าใช้ไม่ได้ รอบใหม่ล็อกอินได้", async () => {
  const email = newEmail();
  const first = await loginOk(email);

  const resent = await post("/login/resend_otp", { email, hash: first.hash });
  assert.equal(resent.status, 200, resent.text);
  assert.equal(resent.json.success, true);
  assert.notEqual(resent.json.hash, first.hash);
  assert.notEqual(resent.json.ref, first.ref);
  assert.equal(lastMail().ref, resent.json.ref);
  const otp2 = lastMail().otp;
  assert.ok(!resent.text.includes(otp2), "response ห้ามมี OTP");

  const oldOne = await post("/login/verify_otp", { email, otp: first.otp, hash: first.hash });
  assert.equal(oldOne.status, 400);

  const newOne = await post("/login/verify_otp", { email, otp: otp2, hash: resent.json.hash });
  assert.equal(newOne.status, 200, newOne.text);
  assert.equal(typeof newOne.json.token, "string");
});

test("Resend: ใช้ hash ที่ได้จาก /signup/send_otp (ไม่ได้ผ่านรหัสผ่าน) เป็นหลักฐานไม่ได้ และไม่ส่งอีเมล", async () => {
  const email = newEmail();
  setUser(email);
  const general = await sendGeneralOtp(email);
  const before = sent.length;

  const r = await post("/login/resend_otp", { email, hash: general.hash });
  assert.equal(r.status, 400);
  assert.equal(typeof r.json.message, "string");
  assert.equal(sent.length, before);

  const missing = await post("/login/resend_otp", { email });
  assert.equal(missing.status, 400);
  const garbage = await post("/login/resend_otp", {});
  assert.equal(garbage.status, 400);
});

test("OTP จาก /signup/send_otp ยังใช้สมัคร/รีเซ็ตรหัสผ่านได้ครั้งเดียว และเดาผิดมี attempts_left", async () => {
  const email = newEmail();
  setUser(email);
  const { hash, otp } = await sendGeneralOtp(email);

  const bad = await post("/login/reset_password/verify_and_reset", { email, otp: wrongOtp(otp), hash, new_password: "x" });
  assert.equal(bad.status, 400);
  assert.equal(bad.json.attempts_left, 4);

  const ok = await post("/login/reset_password/verify_and_reset", { email, otp, hash, new_password: "n3w-passw0rd!" });
  assert.equal(ok.status, 200, ok.text);

  const replay = await post("/login/reset_password/verify_and_reset", { email, otp, hash, new_password: "other" });
  assert.equal(replay.status, 400, "OTP ต้องใช้ได้ครั้งเดียว");
});

test("rate limit: ขอ OTP (send_otp) ของอีเมลเดียวกันเกิน 5 ครั้ง ได้ 429 + Retry-After และไม่ส่งอีเมลเพิ่ม", async () => {
  const email = newEmail();
  for (let i = 0; i < 5; i++) await sendGeneralOtp(email);
  const mails = sent.length;

  const r = await post("/signup/send_otp", { email });
  assert.equal(r.status, 429);
  assert.ok(Number(r.headers.get("retry-after")) > 0);
  assert.equal(typeof r.json.message, "string");
  assert.equal(typeof r.json.error, "string", "แอปบางหน้าอ่าน error บางหน้าอ่าน message ต้องมีทั้งคู่");
  assert.equal(sent.length, mails);
});

test("rate limit: คนขอ OTP (general) ของอีเมลเหยื่อรัว ๆ ต้องไม่บล็อกเหยื่อที่ล็อกอินด้วยรหัสผ่านถูก", async () => {
  const email = newEmail();
  for (let i = 0; i < 5; i++) await sendGeneralOtp(email);
  assert.equal((await post("/signup/send_otp", { email })).status, 429);

  setUser(email);
  const login = await post("/login", { email, password: PASSWORD });
  assert.equal(login.status, 200, login.text);
});

test("send_otp: อีเมลรูปแบบผิด/ไม่ใช่ string ถูกปฏิเสธโดยไม่ส่งอีเมล", async () => {
  for (const email of ["not-an-email", 123, { a: 1 }, ["a@b.co"]]) {
    const r = await post("/signup/send_otp", { email });
    assert.equal(r.status, 400, JSON.stringify(email));
  }
  assert.equal(sent.length, 0);
});

test("ไม่มี OTP_SECRET: ไม่ออก OTP (ไม่ fallback เป็นค่าเริ่มต้น)", async () => {
  delete process.env.OTP_SECRET;
  const email = newEmail();
  const r = await post("/signup/send_otp", { email });
  assert.equal(r.status, 500);
  assert.equal(sent.length, 0);
});
