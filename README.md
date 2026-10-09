# Nexa_Sketch70

## ตั้งค่า `.env` ที่เกี่ยวกับ OTP

| ตัวแปร | จำเป็น | อธิบาย |
|---|---|---|
| `OTP_SECRET` | **ต้องมี** | สตริงสุ่มยาวอย่างน้อย 32 ตัวอักษร ถ้าไม่ตั้งหรือสั้นเกินไป เซิร์ฟเวอร์จะไม่เริ่มทำงาน (ไม่มีค่าเริ่มต้นอีกแล้ว) สร้างได้ด้วย `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"` |
| `OTP_EXPIRE_MINUTES` | ไม่ | อายุ OTP เป็นนาที (ค่าเริ่มต้น 1) |
| `TRUST_PROXY` | ไม่ | ตั้งเมื่อรันหลัง reverse proxy / ngrok เช่น `1` (เชื่อ proxy 1 ชั้น) ถ้าไม่ตั้ง rate limit จะเห็นทุกคำขอเป็น IP ของ proxy |
| `OTP_ALLOW_GENERAL_AT_LOGIN` | ไม่ | **ชั่วคราวเท่านั้น** ตั้งเป็น `true` ระหว่างรอแอปรุ่นที่ Resend ผ่าน `/auth/login/resend_otp` (ดูด้านล่าง) เปิดแล้วช่องโหว่เดา OTP โดยไม่ต้องรู้รหัสผ่านจะกลับมาในระดับที่ช้าลง ให้เอาออกทันทีที่แอปรุ่นใหม่ถูกใช้งาน |

หมายเหตุ: เปลี่ยน `OTP_SECRET` หรือ restart เซิร์ฟเวอร์ทำให้ OTP ที่ผู้ใช้กำลังรอใช้ไม่ได้ ต้องขอรหัสใหม่

## ระบบ OTP

OTP แต่ละรอบเป็น challenge ที่ Backend จำสถานะไว้ในหน่วยความจำ (ใช้ได้กับการรัน instance เดียว)

- ถูกต้องแล้วใช้ได้ **ครั้งเดียว** เดาผิดครบ **5 ครั้ง** รอบนั้นถูกยกเลิก
- ขอ OTP ได้ไม่เกิน **5 ครั้งต่อ 15 นาที** ต่ออีเมลต่อประเภท
- มี 2 ประเภท
  - `login`: ออกโดย `/auth/login` หลังตรวจรหัสผ่านแล้วเท่านั้น ใช้ได้ที่ `/auth/login/verify_otp`
  - `general`: ออกโดย `/auth/signup/send_otp` ใช้ได้กับสมัครสมาชิกและรีเซ็ตรหัสผ่าน ใช้ล็อกอินไม่ได้
- แต่ละรอบมี `ref` (รหัสอ้างอิง 6 ตัว) ที่แสดงในอีเมล (หัวเรื่องและเนื้อหา) เพื่อจับคู่กับรอบที่หน้าจอรออยู่

### API

| Endpoint | Response ที่เพิ่ม/เปลี่ยน |
|---|---|
| `POST /auth/signup/send_otp` `{email}` | `200 {success, hash, ref}` |
| `POST /auth/login` `{email, password}` | `200 {message, hash, ref, tempUser}` |
| `POST /auth/login/resend_otp` `{email, hash}` (ใหม่) | `200 {success, hash, ref}` / `400 {message}` ถ้าเซสชันหมด ต้องล็อกอินใหม่ |
| `POST /auth/login/verify_otp`, `/auth/signup/verify_and_register`, `/auth/login/reset_password/verify_and_reset` | เดาผิด `400 {message, attempts_left}` (`0` = รอบนี้ถูกยกเลิก ต้องขอรหัสใหม่) |
| ทุก endpoint ที่ขอ/ยืนยัน OTP | `429 {message, error, retry_after_seconds?}` + header `Retry-After` เมื่อถูกจำกัด |

`hash` ยังเป็นรูปแบบเดิม แอปรุ่นเก่าอ่านแค่ field ที่เคยใช้ จึงไม่พังจาก field ที่เพิ่ม ยกเว้นข้อเดียวคือ **ปุ่ม Resend ของหน้า OTP login**

### ปุ่ม Resend ของหน้า OTP login

แอปรุ่นเดิมกด Resend แล้วเรียก `/auth/signup/send_otp` ซึ่งใครก็เรียกได้โดยไม่ต้องรู้รหัสผ่าน แล้วเอา OTP นั้นมายืนยันที่ `/auth/login/verify_otp` เมื่อ Backend ปฏิเสธ OTP ประเภท `general` ที่ login (ซึ่งเป็นการปิดช่องโหว่) ปุ่มนี้ในแอปรุ่นเดิมจึงใช้ไม่ได้

แอปรุ่นใหม่ต้องเรียก `POST /auth/login/resend_otp` พร้อม `{email, hash}` โดย `hash` คือของรอบ login ล่าสุด ใช้ได้ภายใน 10 นาทีหลัง OTP นั้นหมดอายุ และต่อเนื่องได้ไม่เกิน 15 นาทีนับจากตอนผ่านรหัสผ่าน เกินนั้นต้องกรอกรหัสผ่านใหม่

ถ้าต้อง deploy Backend ก่อนที่แอปรุ่นใหม่จะพร้อม ให้ตั้ง `OTP_ALLOW_GENERAL_AT_LOGIN=true` ชั่วคราว (เซิร์ฟเวอร์จะแจ้งเตือนใน log ตอนเริ่ม)

## ทดสอบ

```
npm test         # ต้องใช้ Node 22.3 ขึ้นไป (ใช้ module mock ของ node:test)
npm run typecheck
```
