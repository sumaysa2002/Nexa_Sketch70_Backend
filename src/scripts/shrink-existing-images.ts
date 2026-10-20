/**
 * ย่อ + เขียนรูปเก่าที่อยู่ใน uploads/ ใหม่ ด้วยกฎเดียวกับตอนอัปโหลด (src/helper/image.ts)
 */
import fs from "fs";
import path from "path";
import { eq } from "drizzle-orm";

import { db } from "../db/index.js";
import { points, users } from "../db/schema.js";

import {
  normalizeImage,
  POINT_IMAGE_OPTIONS,
  PROFILE_IMAGE_OPTIONS,
  SIGNATURE_IMAGE_OPTIONS,
  type NormalizeOptions,
} from "../helper/image.js";

const APPLY      = process.argv.includes("--apply");
const CLEAN_TEMP = process.argv.includes("--clean-temp");
const MIN_SAVING = 0.10; // ต้องเล็กลงอย่างน้อย 10%

// ต้องตรงกับ IMAGE_FIELDS ใน routes/point_task.ts
const POINT_IMAGE_FIELDS = [
  "point_zoomin_img", "point_zoomout_img", "point_survey_img", "point_controller_img",
  "n_survey_img", "s_survey_img", "e_survey_img", "w_survey_img",
  "draw_img", "details_img", "draw_description_img",
] as const;

const stats = { checked: 0, shrunk: 0, skipped: 0, missing: 0, failed: 0, before: 0, after: 0 };
const mb = (n: number) =>
  n >= 1024 * 1024 ? (n / 1024 / 1024).toFixed(1) + "MB" : Math.round(n / 1024) + "KB";

function safeUnlink(p?: string) {
  if (p && fs.existsSync(p)) fs.unlinkSync(p);
}

/// ── ประมวลผล 1 ไฟล์ (updateDb ถูกเรียกเฉพาะเมื่อชื่อไฟล์เปลี่ยน) ──────────────
async function processFile(
  dir: string,
  filename: string,
  opts: NormalizeOptions,
  updateDb: (newName: string) => Promise<void>,
): Promise<void> {
  stats.checked++;
  const src = path.join(dir, filename);

  if (path.basename(filename) !== filename || !fs.existsSync(src)) {
    stats.missing++;
    console.log(`  ไม่พบไฟล์  ${src}`);
    return;
  }

  const before = fs.statSync(src).size;
  // ไฟล์ผลลัพธ์ชั่วคราวในโฟลเดอร์เดียวกัน >> rename ทับได้แบบ atomic
  const tmpOut = path.join(dir, `.shrink_${process.pid}_${Date.now()}_${filename}.tmp`);

  let result;
  try {
    result = await normalizeImage(src, opts, tmpOut);
  } catch (e) {
    stats.failed++;
    console.log(`  ผิดพลาด   ${src}: ${(e as Error).message}`);
    return;
  }

  // ไม่คุ้มที่จะแทนที่
  if (result.size > before * (1 - MIN_SAVING)) {
    safeUnlink(result.path);
    stats.skipped++;
    return;
  }

  const sameExt = path.extname(filename).toLowerCase() === result.ext;
  const newName = sameExt ? filename : path.basename(filename, path.extname(filename)) + result.ext;

  stats.shrunk++;
  stats.before += before;
  stats.after  += result.size;
  console.log(`  ${APPLY ? "ย่อแล้ว " : "จะย่อ  "}  ${src}  ${mb(before)} -> ${mb(result.size)}${sameExt ? "" : `  (เปลี่ยนชื่อเป็น ${newName})`}`);

  if (!APPLY) {
    safeUnlink(result.path);
    return;
  }

  if (sameExt) {
    // rename ในโฟลเดอร์เดียวกัน = แทนที่แบบ atomic
    fs.renameSync(result.path, src);
    return;
  }

  const dest = path.join(dir, newName);
  if (fs.existsSync(dest)) {
    safeUnlink(result.path);
    stats.failed++;
    console.log(`  ผิดพลาด   มีไฟล์ ${dest} อยู่แล้ว ข้าม`);
    return;
  }
  fs.renameSync(result.path, dest);
  try {
    await updateDb(newName);
  } catch (e) {
    safeUnlink(dest); // DB ไม่เปลี่ยน >> คืนสภาพเดิม
    stats.failed++;
    console.log(`  ผิดพลาด   อัปเดต DB ไม่สำเร็จ: ${(e as Error).message}`);
    return;
  }
  safeUnlink(src); // ลบไฟล์เดิมหลัง DB อัปเดตสำเร็จแล้วเท่านั้น
}

/// ── ลบไฟล์ temp ที่ค้างจาก request ที่ล้มกลางทาง ─────────────────────
function cleanTemp() {
  const cutoff = Date.now() - 60 * 60 * 1000;
  const targets: [string, RegExp][] = [
    ["uploads/point/temp", /^temp_/],
    ["uploads/profiles",   /^tmp_/],
  ];
  let count = 0;
  for (const [dir, pattern] of targets) {
    if (!fs.existsSync(dir)) continue;
    for (const name of fs.readdirSync(dir)) {
      const p = path.join(dir, name);
      const st = fs.statSync(p);
      if (!st.isFile() || !pattern.test(name) || st.mtimeMs > cutoff) continue;
      console.log(`  ${APPLY ? "ลบแล้ว" : "จะลบ"}  ${p}`);
      if (APPLY) fs.unlinkSync(p);
      count++;
    }
  }
  console.log(`ไฟล์ temp ที่ค้าง: ${count} ไฟล์`);
}

async function main() {
  console.log(APPLY ? "โหมดทำจริง (--apply)\n" : "โหมดดูผล (ยังไม่แก้ไฟล์ใด ๆ) เพิ่ม --apply เพื่อทำจริง\n");

  // ── รูปหมุด ──
  console.log("รูปหมุด");
  const allPoints = await db.select().from(points);
  for (const p of allPoints) {
    const dir = path.join("uploads", "point", String(p.project_id), String(p.id));
    for (const field of POINT_IMAGE_FIELDS) {
      const filename = (p as any)[field] as string | null;
      if (!filename) continue;
      await processFile(dir, filename, POINT_IMAGE_OPTIONS, async (newName) => {
        await db.update(points).set({ [field]: newName } as any).where(eq(points.id, p.id));
      });
    }
  }

  // ── รูปโปรไฟล์ / ลายเซ็น ──
  console.log("\nรูปโปรไฟล์ / ลายเซ็น");
  const allUsers = await db
    .select({ id: users.id, profile_img: users.profile_img, signature: users.signature })
    .from(users);
  for (const u of allUsers) {
    if (u.profile_img) {
      await processFile("uploads/profiles", u.profile_img, PROFILE_IMAGE_OPTIONS, async (newName) => {
        await db.update(users).set({ profile_img: newName }).where(eq(users.id, u.id));
      });
    }
    if (u.signature) {
      await processFile("uploads/signatures", u.signature, SIGNATURE_IMAGE_OPTIONS, async (newName) => {
        await db.update(users).set({ signature: newName }).where(eq(users.id, u.id));
      });
    }
  }

  if (CLEAN_TEMP) {
    console.log("");
    cleanTemp();
  }

  console.log(
    `\nสรุป: ตรวจ ${stats.checked} ไฟล์, ${APPLY ? "ย่อแล้ว" : "จะย่อ"} ${stats.shrunk}, ` +
    `ข้าม ${stats.skipped} (เล็กพออยู่แล้ว), ไม่พบไฟล์ ${stats.missing}, ผิดพลาด ${stats.failed}`
  );
  if (stats.shrunk > 0) {
    console.log(`พื้นที่: ${mb(stats.before)} -> ${mb(stats.after)} (ลดลง ${mb(stats.before - stats.after)})`);
  }
}

main()
  .then(() => process.exit(0))
  .catch((e) => {
    console.error(e);
    process.exit(1);
  });