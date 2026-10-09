import {
  pgTable,
  serial,
  text,
  integer,
  numeric,
  timestamp,
  date,
  index
} from "drizzle-orm/pg-core";

/* =======================
   USERS TABLE
======================= */
export const users = pgTable("users", {

  id:             serial("id").primaryKey(),

  title_name:     text("title_name").notNull(),
  first_name:     text("first_name").notNull(),
  last_name:      text("last_name").notNull(),
  phone:          text("phone").notNull(),
  email:          text("email").notNull().unique(),
  password:       text("password").notNull(),            // hashedPassword

  profile_img:    text("profile_img"),                   // userID_profile_img_{timestamp}.jpg
  
  job_position:   text("job_position"),
  job_level:      text("job_level"),
  job_office:     text("job_office"),
  job_department: text("job_department"),

  admin:          text("admin"),                         // id admin ที่เป็นคนอนุมัติ user
  status:         text("status"),                        // admin | user | null = ยังไม่อนุมัติจาก admin
  signature:      text("signature"),                     // userID_signature_img_{timestamp}.jpg

});

/* =======================
   USERS HISTORY TABLE
======================= */
export const usersHistory = pgTable("users_history", {

  id:                              serial("id").primaryKey(),

  user_id:                         integer("user_id").notNull(),                                          // FK → users.id

  user_create:                     integer("user_create"),                                                // users.id
  time_user_create:                timestamp("time_user_create", { withTimezone: true }),

  admin_approved_user:             integer("admin_approved_user"),                                        // users.id ของ admin ที่เป็นคนอนุมัติ user
  time_admin_approved_user:        timestamp("time_admin_approved_user", { withTimezone: true }),

  admin_revoke_approval_user:      integer("admin_revoke_approval_user"),
  time_admin_revoke_approval_user: timestamp("time_admin_revoke_approval_user", { withTimezone: true }),  // users.id ของ admin ที่เป็นคนถอนการอนุมัติ user

  user_updated:                    integer("user_updated"),
  time_user_updated:               timestamp("time_user_updated", { withTimezone: true }),

  user_delete:                     integer("user_delete"),
  time_user_delete:                timestamp("time_user_delete", { withTimezone: true }),
  
});

/* =======================
   OTP CHALLENGES TABLE
   เก็บสถานะ OTP ฝั่ง server (ใช้ได้ครั้งเดียว / จำกัดจำนวนครั้งที่เดา / ผูกกับ purpose)
   ทุกครั้งที่ระบบส่ง OTP จะเพิ่ม 1 แถวในตาราง
======================= */
export const otpChallenges = pgTable("otp_challenges", {
    id:          text("id").primaryKey(),                                   // random 32 bytes (hex) >> เป็น Ref OTP
    email:       text("email").notNull(),                                   
    purpose:     text("purpose").notNull(),                                 // signup | login | reset_password
    otp_hash:    text("otp_hash").notNull(),                                // HMAC ของ OTP (ไม่เก็บ OTP ตัวจริง)
    attempts:    integer("attempts").notNull().default(0),                  // จำนวนครั้งที่กรอกไปแล้ว
    expires_at:  timestamp("expires_at", { withTimezone: true }).notNull(), // เวลาหมดอายุ (สร้าง + 5 นาที)
    consumed_at: timestamp("consumed_at", { withTimezone: true }),          // null = ยังใช้ได้ >> มีค่า = ปิดแล้ว (ใช้สำเร็จ หรือถูกแทนที่ด้วยรหัสใหม่)
    verified_at: timestamp("verified_at", { withTimezone: true }),          // ยืนยันสำเร็จเมื่อไร (ใช้รีเซ็ตการนับโควตาขอ OTP)
    created_at:  timestamp("created_at", { withTimezone: true }).notNull().defaultNow(), // เวลาสร้าง ใช้คำนวณ cooldown 60 วินาที และโควตาต่อชั่วโมง
  },
  (t) => [index("otp_challenges_email_purpose_idx").on(t.email, t.purpose, t.created_at)]
);


/* =======================
   TYPES
======================= */
export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;

export type UserHistory = typeof usersHistory.$inferSelect;
export type NewUserHistory = typeof usersHistory.$inferInsert;

export type OtpChallenge = typeof otpChallenges.$inferSelect;


//---------------------------------------------------------------------------------------------------


/* =======================
   PROJECTS TABLE
======================= */
export const projects = pgTable("projects", {

  id:                serial("id").primaryKey(),

  name_project_id:   text("name_project_id"),            // ชื่อ ID โครงการ
  project_name:      text("project_name").notNull(),     // ชื่อโครงการ
  project_details:   text("project_details"),            // รายละเอียด
  province:          text("province"),                   // "จ.1, จ.2, จ.3"

  sensor:            text("sensor"),                     // sensor
  gsd_num:           integer("gsd_num"),                 // ค่า GSD
  gsd_unit:          text("gsd_unit"),                   // หน่วย GSD

  survey_main:       text("survey_main"),                // วิธีรังวัดหลัก
  survey_sub:        text("survey_sub"),                 // วิธีรังวัดย่อย

  project_start_date: date("project_start_date"),        // วันเริ่มต้นการสำรวจ
  project_end_date:   date("project_end_date"),          // วันสิ้นสุดการสำรวจ

  project_note:      text("project_note"),               // หมายเหตุ

});

/* =======================
   PROJECT MEMBERS TABLE
======================= */
export const projectMembers = pgTable("project_members", {

  id:               serial("id").primaryKey(),

  project_id:       integer("project_id").notNull(),         // FK → projects.id
  user_id:          integer("user_id").notNull(),            // FK → users.id

  time_add_members: timestamp("time_add_members", { withTimezone: true,}).notNull(),
  
});

/* =======================
   PROJECT HISTORY TABLE
======================= */
export const projectHistory = pgTable("project_history", {

  id:         serial("id").primaryKey(),

  project_id: integer("project_id").notNull(),                                         // FK → projects.id

  project_user_creator:  integer("project_user_creator"),                              // users.id
  project_time_created:  timestamp("project_time_created", { withTimezone: true }),

  project_user_updated:  integer("project_user_updated"),                              // users.id
  project_time_updated:  timestamp("project_time_updated", { withTimezone: true }),

  project_user_delete:   integer("project_user_delete"),                               // users.id
  project_time_delete:   timestamp("project_time_delete",   { withTimezone: true }),
  
});

/* =======================
   TYPES
======================= */
export type Project        = typeof projects.$inferSelect;
export type NewProject     = typeof projects.$inferInsert;

export type ProjectMember  = typeof projectMembers.$inferSelect;
export type NewProjectMember = typeof projectMembers.$inferInsert;

export type ProjectHistory = typeof projectHistory.$inferSelect;
export type NewProjectHistory = typeof projectHistory.$inferInsert;


//---------------------------------------------------------------------------------------------------


/* =======================
   Points TABLE
======================= */
export const points = pgTable("points", {

  id:                  serial("id").primaryKey(),

  project_id:          integer("project_id").notNull(),                           // FK → projects.id
  point_name:          text("point_name").notNull(),

  northing:             numeric("northing", { precision: 10, scale: 3 }),
  easting:              numeric("easting",  { precision: 9, scale: 3 }),
  height_m:             numeric("height_m", { precision: 9, scale: 3 }),
  ellipsoidal_m:        numeric("ellipsoidal_m", { precision: 9, scale: 3 }),
  antenna_m:            numeric("antenna_m", { precision: 9, scale: 3 }),         // สามารถเป็นค่าติดลบได้
  datum:                text("datum"),
  utm:                  text("utm"),
  egm:                  text("egm"),

  survey_main:          text("survey_main"),
  survey_sub:           text("survey_sub"),

  gdop_m:               numeric("gdop_m", { precision: 6, scale: 1 }),
  pdop_m:               numeric("pdop_m", { precision: 6, scale: 1 }),
  hdop_m:               numeric("hdop_m", { precision: 8, scale: 3 }),
  dcq_m:                numeric("dcq_m",  { precision: 8, scale: 3 }),

  tambon:               text("tambon"),
  amphoe:               text("amphoe"),
  province:             text("province"),
  point_date:           date("point_date"),                                     // วันที่สำรวจ

  point_zoomin_img:     text("point_zoomin_img"),                               // projectID_pointID_1_point_zoomin_img_{timestamp}.jpg
  point_zoomout_img:    text("point_zoomout_img"),                              // projectID_pointID_2_point_zoomout_img_{timestamp}.jpg

  job:                  text("job"),
  gnss:                 text("gnss"),
  rf_1:                 text("rf_1"),
  distance_m_1:         numeric("distance_m_1", { precision: 10, scale: 2 }),
  az_1:                 integer("az_1"),
  rf_2:                 text("rf_2"),
  distance_m_2:         numeric("distance_m_2", { precision: 10, scale: 2 }),
  az_2:                 integer("az_2"),

  point_survey_img:     text("point_survey_img"),                               // projectID_pointID_3_point_survey_img_{timestamp}.jpg
  point_controller_img: text("point_controller_img"),                           // projectID_pointID_4_point_controller_img_{timestamp}.jpg
  n_survey_img:         text("n_survey_img"),                                   // projectID_pointID_5_N_survey_img_{timestamp}.jpg
  s_survey_img:         text("s_survey_img"),                                   // projectID_pointID_6_S_survey_img_{timestamp}.jpg
  e_survey_img:         text("e_survey_img"),                                   // projectID_pointID_7_E_survey_img_{timestamp}.jpg
  w_survey_img:         text("w_survey_img"),                                   // projectID_pointID_8_W_survey_img_{timestamp}.jpg

  draw_img:             text("draw_img"),                                       // projectID_pointID_9_draw_img_{timestamp}.jpg
  details_img:          text("details_img"),                                    // projectID_pointID_10_details_img_{timestamp}.jpg
  
  draw_description_img: text("draw_description_img"),                           // projectID_pointID_11_draw_description_img_{timestamp}.jpg

  survey_technician: integer("survey_technician"),                              // users.id
  survey_qc:         integer("survey_qc"),                                      // users.id

  point_note:      text("point_note"),

});

/* =======================
   POINT DATA JSON TABLE
======================= */
export const pointDataJson = pgTable("point_data_json", {

  id:       serial("id").primaryKey(),

  point_id: integer("point_id")                                      // FK → point.id
              .notNull()
              .unique()                                              // 1 point : 1 row
              .references(() => points.id, { onDelete: "cascade" }), // ลบ point แล้วลบ row อัตโนมัติ

  draw_data_json:    text("draw_data_json"),
  details_data_json: text("details_data_json"),
  
});

/* =======================
   Point HISTORY TABLE
======================= */
export const pointHistory = pgTable("point_history", {

  id:                  serial("id").primaryKey(),

  project_id:          integer("project_id").notNull(),                          // FK → project.id
  point_id:            integer("point_id").notNull(),                            // FK → point.id

  point_user_creator:  integer("point_user_creator"),
  point_time_created:  timestamp("point_time_created", { withTimezone: true }),

  point_user_updated:  integer("point_user_updated"),
  point_time_updated:  timestamp("point_time_updated", { withTimezone: true }),

  point_user_delete:   integer("point_user_delete"),
  point_time_delete:   timestamp("point_time_delete",   { withTimezone: true }),

});

/* =======================
   TYPES
======================= */
export type Point        = typeof points.$inferSelect;
export type NewPoint     = typeof points.$inferInsert;

export type PointDataJson    = typeof pointDataJson.$inferSelect;
export type NewPointDataJson = typeof pointDataJson.$inferInsert;

export type PointHistory = typeof pointHistory.$inferSelect;
export type NewPointHistory = typeof pointHistory.$inferInsert;
