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
  refCode: string;   // รหัสอ้างอิงของ OTP รอบนี้ (แสดงตรงกับหน้า OTP ในแอป)
  expiresIn: number; // นาที
}

export const sendOTPEmail = async ({ email, otp, refCode, expiresIn }: SendEmailParams) => {
  const mailOptions = {

    // ผู้ส่ง
    from: `"${process.env.SYSTEM_MAIL_NAME}" <${process.env.GMAIL_USER}>`,
    
    // ผู้รับ
    to: email,
    // ใส่ Ref ใน subject → อีเมลแต่ละรอบแยกกันชัดเจน (Gmail ไม่รวมเป็น thread เดียว)
    subject: `[Nexa Sketch] Email verification code — Ref: ${refCode}`,
    html: `

      <div style="text-align:center;">
        <img src="https://cdn-icons-png.flaticon.com/512/3064/3064197.png" width="100" />

        <h2 style="
              margin: 0 0 20px;
              font-family: Arial, Tahoma, sans-serif;
              font-size: 22px;
              font-weight: 600;
              color: #222222;
            ">
              รหัสยืนยันตัวตนของคุณคือ
        </h2>

        <div style="
              font-family: Arial, Tahoma, sans-serif;
              font-size: 32px;
              font-weight: bold;
              letter-spacing: 5px;
              color: #1a73e8;
              margin: 20px 0;
            ">
              ${otp}
        </div>

        <p style="
              font-family: Arial, Tahoma, sans-serif;
              font-size: 16px;
              margin: 0 0 16px;
              color: #333333;
            ">
              รหัสอ้างอิง (Ref):
              <b style="letter-spacing: 2px;">
                ${refCode}
              </b>
        </p>

        <p style="
              font-family: Arial, Tahoma, sans-serif;
              font-size: 15px;
              color: #333333;
            ">
              รหัสนี้มีอายุการใช้งาน
              <b>${expiresIn} นาที</b>
              และกรอกผิดได้ไม่เกิน
              <b>5 ครั้ง</b>
        </p>

        <p style="
              font-family: Arial, Tahoma, sans-serif;
              color: #666666;
              font-size: 13px;
            ">
              โปรดตรวจสอบว่า Ref ในอีเมลนี้ตรงกับ Ref
              ที่แสดงในแอปพลิเคชัน
        </p>

        <p style="
              font-family: Arial, Tahoma, sans-serif;
              color: #999999;
              font-size: 13px;
              margin-top: 30px;
            ">
              หากคุณไม่ได้ทำการสมัครสมาชิกหรือเข้าสู่ระบบ
              แอปพลิเคชัน Nexa Sketch โปรดเพิกเฉยต่อข้อความนี้
        </p>
 
      </div>

    `,
  };

  return transporter.sendMail(mailOptions);
};
