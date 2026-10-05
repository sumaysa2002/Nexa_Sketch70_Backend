import crypto from "crypto";
import otpGenerator from "otp-generator";
import { sendOTPEmail } from "../services/emailer.service.js";

const OTP_SECRET = process.env.OTP_SECRET || "default_secret";
const EXPIRE_MINUTES = Number(process.env.OTP_EXPIRE_MINUTES) || 1; //เลขเวลา

interface OTPParams {
  email: string;
}

interface VerifyParams {
  email: string;
  otp: string;
  hash: string;
}

/// ส่ง OTP
export const sendOTP = async ({ email }: OTPParams): Promise<string> => {

  // 1. สร้างรหัส OTP 6 หลัก
  const otp = otpGenerator.generate(6, {
    digits: true,
    lowerCaseAlphabets: false,
    upperCaseAlphabets: false,
    specialChars: false,
  });

  // 2. คำนวณเวลาหมดอายุ
  const ttl = EXPIRE_MINUTES * 60 * 1000; // ตอนนี้จะเป็น 60,000 ms (1 นาที)
  const expires = Date.now() + ttl;

  // 3. สร้าง Hash (Email + OTP + Timestamp)
  const data = `${email}.${otp}.${expires}`;
  const hashValue = crypto.createHmac("sha256", OTP_SECRET).update(data).digest("hex");
  const fullHash = `${hashValue}.${expires}`;

  // แสดงรหัสใน Terminal
  console.log("-----------------------------------------");
  console.log(`[OTP DEBUG] Target Email: ${email}`);
  console.log(`[OTP DEBUG] รหัส OTP คือ: ${otp}`);
  try {
    await sendOTPEmail({ email, otp, expiresIn: EXPIRE_MINUTES });
    console.log(`✅ [EMAIL] ส่งเมลสำเร็จแล้ว!`);
  } catch (error) {
    console.error("❌ [EMAIL ERROR] ส่งเมลไม่สำเร็จ:", error);
    throw new Error("ไม่สามารถส่งอีเมล OTP ได้ กรุณาตรวจสอบการตั้งค่า Server");
  }
  console.log("-----------------------------------------");

  return fullHash; // ส่ง fullHash กลับไปให้ Flutter
};


/// ตรวจสอบ OTP
export const verifyOTP = ({ email, otp, hash }: VerifyParams): boolean => {
  try {
    const [hashValue, expires] = hash.split(".");
    if (!hashValue || !expires) return false;

    // ตรวจสอบเวลาหมดอายุ
    if (Date.now() > parseInt(expires)) return false;

    // คำนวณ Hash ใหม่จากข้อมูลที่ส่งมา แล้วเทียบกับ Hash เดิม
    const data = `${email}.${otp}.${expires}`;
    const newCalculatedHash = crypto
      .createHmac("sha256", OTP_SECRET)
      .update(data)
      .digest("hex");

    return newCalculatedHash === hashValue;
  } catch (err) {
    return false;
  }
};