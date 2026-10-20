import sharp, { type Metadata } from "sharp";
import fs from "fs";

/* ============================================================
   ประมวลผลรูปภาพฝั่ง server ด้วย sharp
   - เขียนรูปใหม่ทุกไฟล์ (re-encode) >> ตัด EXIF/GPS, ตัดข้อมูลแปลกปลอมของไฟล์
   - ย่อขนาดตามประเภทรูป
   - PNG เก็บเป็น PNG (ภาพวาด/ภาพที่มีพื้นใส) ส่วนอื่นแปลงเป็น JPEG
============================================================ */

// ไม่ต้อง cache ไฟล์ใน memory (server ประมวลผลรูปแต่ละรูปครั้งเดียว)
sharp.cache(false);

/// รูปที่มีพิกเซลเกิน ปฏิเสธทันที
const MAX_INPUT_PIXELS = 60_000_000; // ประมาณ 60 ล้านพิกเซล

export interface NormalizeOptions {
  maxWidth: number;
  maxHeight: number;
  jpegQuality?: number;
}

/// ขนาดสูงสุดของรูปแต่ละประเภท
export const POINT_IMAGE_OPTIONS:     NormalizeOptions = { maxWidth: 2560, maxHeight: 2560, jpegQuality: 85 };
export const PROFILE_IMAGE_OPTIONS:   NormalizeOptions = { maxWidth: 512,  maxHeight: 512,  jpegQuality: 85 };
export const SIGNATURE_IMAGE_OPTIONS: NormalizeOptions = { maxWidth: 1200, maxHeight: 600,  jpegQuality: 90 };

export interface NormalizedImage {
  path: string;
  ext: ".jpg" | ".png";
  size: number;
}

/// error ไฟล์เสีย
export class ImageProcessError extends Error {}

function safeUnlink(p?: string) {
  if (p && fs.existsSync(p)) fs.unlinkSync(p);
}

/// ── เขียนรูปใหม่จาก srcPath >> คืน path ของไฟล์ใหม่ ──────────
export async function normalizeImage(
  srcPath: string,
  opts: NormalizeOptions,
  outPath?: string,
): Promise<NormalizedImage> {
  let meta: Metadata;
  try {
    meta = await sharp(srcPath, { limitInputPixels: MAX_INPUT_PIXELS }).metadata();
  } catch {
    throw new ImageProcessError("อ่านข้อมูลรูปภาพไม่ได้ หรือรูปมีขนาดใหญ่เกินไป");
  }
  if (!meta.width || !meta.height) {
    throw new ImageProcessError("อ่านข้อมูลรูปภาพไม่ได้");
  }

  const keepPng = meta.format === "png";
  const ext: NormalizedImage["ext"] = keepPng ? ".png" : ".jpg";
  const out = outPath ?? `${srcPath}.norm${ext}`;

  let pipeline = sharp(srcPath, { limitInputPixels: MAX_INPUT_PIXELS, failOn: "error" })
    .rotate()
    .resize({
      width: opts.maxWidth,
      height: opts.maxHeight,
      fit: "inside",
      withoutEnlargement: true,
    });

  pipeline = keepPng
    ? pipeline.png({ compressionLevel: 9, adaptiveFiltering: true })
    : pipeline
        .flatten({ background: "#ffffff" }) // พื้นใส (เช่น webp) >> พื้นขาว
        .jpeg({ quality: opts.jpegQuality ?? 85, mozjpeg: true });

  // sharp ไม่คัดลอก metadata ไปไฟล์ใหม่
  try {
    await pipeline.toFile(out);
  } catch {
    safeUnlink(out);
    throw new ImageProcessError("แปลงไฟล์รูปภาพไม่สำเร็จ");
  }

  return { path: out, ext, size: fs.statSync(out).size };
}

/// ไฟล์จาก multer
interface UploadedFileLike {
  path: string;
  originalname: string;
  mimetype: string;
  size: number;
  fieldname: string;
}

/// ── แทนที่ไฟล์ temp ของ multer ด้วยไฟล์ที่ผ่าน normalize แล้ว ──────────────────
export async function normalizeUploadedFiles(
  files: UploadedFileLike[],
  optionsFor: (file: UploadedFileLike) => NormalizeOptions,
): Promise<void> {
  for (const file of files) {
    const result = await normalizeImage(file.path, optionsFor(file));
    safeUnlink(file.path);
    file.path         = result.path;
    file.originalname = `image${result.ext}`;
    file.mimetype     = result.ext === ".png" ? "image/png" : "image/jpeg";
    file.size         = result.size;
  }
}