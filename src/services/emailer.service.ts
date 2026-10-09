import nodemailer from "nodemailer";

// ตั้งค่าตัวส่งเมล
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASSWORD,
  },
});

interface SendEmailParams {
  email: string;
  otp: string;
  ref: string;       // รหัสอ้างอิงของ OTP รอบนี้ (แสดงในอีเมลและหน้า OTP เพื่อให้จับคู่กันได้)
  expiresIn: number; // นาที
}

export const sendOTPEmail = async ({ email, otp, ref, expiresIn }: SendEmailParams) => {
  const mailOptions = {

    // ผู้ส่ง
    from: `"${process.env.SYSTEM_MAIL_NAME}" <${process.env.GMAIL_USER}>`,

    // ผู้รับ
    to: email,
    subject: `รหัสยืนยันตัวตน (OTP) สำหรับแอปพลิเคชัน GNSS [Ref: ${ref}]`,
    html: `

      <div style="text-align:center;">
        <img src="https://cdn-icons-png.flaticon.com/512/3064/3064197.png"
            width="100" />
        <h1 style="letter-spacing:6px;">******</h1>

        <h2>รหัสยืนยันตัวตนของคุณคือ</h2>
        <div style="font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #1a73e8; margin: 20px 0;">
          ${otp}
        </div>
        <p>รหัสอ้างอิง (Ref): <b style="letter-spacing:2px;">${ref}</b></p>
        <p>รหัสนี้มีอายุการใช้งาน <b>${expiresIn} นาที</b></p>
        <p style="color: #666; font-size: 12px;">หากคุณไม่ได้ทำการสมัครสมาชิกหรือเข้าสู่ระบบแอปพลิเคชัน GNSS โปรดเพิกเฉยต่อข้อความนี้</p>
      </div>

    `,
  };

  return transporter.sendMail(mailOptions);
};