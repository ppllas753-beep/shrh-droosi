const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false }
    })
  : null;

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

async function q(sql, params = []) {
  if (!pool) throw new Error('DATABASE_URL missing');
  return pool.query(sql, params);
}

function jsonErr(res, status, message) {
  return res.status(status).json({
    success: false,
    message
  });
}

function publicAdmin(a) {
  return {
    id: a.id,
    username: a.username,
    active: a.active,
    can_manage_content: a.can_manage_content,
    can_manage_admins: a.can_manage_admins,
    can_view_stats: a.can_view_stats,
    can_manage_settings: a.can_manage_settings,
    is_owner: a.is_owner,
    created_at: a.created_at
  };
}

async function log(adminId, action, details = '') {
  try {
    await q(
      'INSERT INTO activity_logs(admin_id,action,details) VALUES($1,$2,$3)',
      [adminId || null, action, details]
    );
  } catch (_) {}
}

async function tokenAdmin(token) {
  if (!token) return null;

  const r = await q(
    `SELECT a.*
     FROM admin_sessions s
     JOIN admins a ON a.id=s.admin_id
     WHERE s.token=$1
     AND s.expires_at>NOW()
     AND a.active=true
     LIMIT 1`,
    [token]
  );

  return r.rows[0] || null;
}

async function auth(req, res, next) {
  try {
    const token =
      req.get('x-admin-token') ||
      ((req.get('authorization') || '')
        .replace(/^Bearer\s+/i, ''));

    const admin = await tokenAdmin(token);

    if (!admin) {
      return jsonErr(
        res,
        401,
        'جلسة الإدارة غير صالحة أو منتهية.'
      );
    }

    req.admin = admin;
    next();

  } catch (e) {
    return jsonErr(
      res,
      500,
      'تعذر التحقق من الجلسة.'
    );
  }
}

function perm(req, res, permission) {
  if (
    req.admin.is_owner ||
    req.admin[permission]
  ) {
    return true;
  }

  jsonErr(
    res,
    403,
    'ليس لديك صلاحية لهذه العملية.'
  );

  return false;
}

async function newToken(id) {
  const token =
    crypto.randomBytes(32).toString('hex');

  await q(
    `INSERT INTO admin_sessions
     (token,admin_id,expires_at)
     VALUES($1,$2,NOW()+INTERVAL '24 hours')`,
    [token, id]
  );

  return token;
}

/* =========================
   DATABASE
========================= */

async function init() {
  if (!pool) return;

  await q(`
    CREATE TABLE IF NOT EXISTS admins (
      id SERIAL PRIMARY KEY,
      username VARCHAR(80) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      can_manage_content BOOLEAN NOT NULL DEFAULT TRUE,
      can_manage_admins BOOLEAN NOT NULL DEFAULT FALSE,
      can_view_stats BOOLEAN NOT NULL DEFAULT TRUE,
      can_manage_settings BOOLEAN NOT NULL DEFAULT FALSE,
      is_owner BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS admin_sessions (
      token TEXT PRIMARY KEY,
      admin_id INTEGER NOT NULL
        REFERENCES admins(id)
        ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL
    );

    CREATE TABLE IF NOT EXISTS semesters (
      id SERIAL PRIMARY KEY,
      name VARCHAR(120) UNIQUE NOT NULL,
      enabled BOOLEAN NOT NULL DEFAULT TRUE
    );

    CREATE TABLE IF NOT EXISTS grades (
      id SERIAL PRIMARY KEY,
      name VARCHAR(120) UNIQUE NOT NULL,
      enabled BOOLEAN NOT NULL DEFAULT TRUE
    );

    CREATE TABLE IF NOT EXISTS subjects (
      id SERIAL PRIMARY KEY,
      name VARCHAR(120) UNIQUE NOT NULL,
      enabled BOOLEAN NOT NULL DEFAULT TRUE
    );

    CREATE TABLE IF NOT EXISTS lessons (
      id SERIAL PRIMARY KEY,
      semester VARCHAR(120),
      grade VARCHAR(120),
      subject VARCHAR(120),
      title VARCHAR(255) NOT NULL,
      description TEXT DEFAULT '',
      video_url TEXT DEFAULT '',
      enabled BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS settings (
      key VARCHAR(120) PRIMARY KEY,
      value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS activity_logs (
      id BIGSERIAL PRIMARY KEY,
      admin_id INTEGER
        REFERENCES admins(id)
        ON DELETE SET NULL,
      action VARCHAR(255) NOT NULL,
      details TEXT DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS visits (
      id BIGSERIAL PRIMARY KEY,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS searches (
      id BIGSERIAL PRIMARY KEY,
      query TEXT NOT NULL,
      grade TEXT DEFAULT '',
      subject TEXT DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  const semesters = [
    'الفصل الدراسي الأول',
    'الفصل الدراسي الثاني'
  ];

  const grades = [
    'الصف الخامس',
    'الصف السادس',
    'الصف السابع',
    'الصف الثامن',
    'الصف التاسع',
    'الصف العاشر',
    'الصف الحادي عشر',
    'الصف الثاني عشر'
  ];

  const subjects = [
    'الرياضيات',
    'الفيزياء',
    'الكيمياء',
    'الأحياء',
    'اللغة الإنجليزية',
    'اللغة العربية',
    'الدراسات الاجتماعية',
    'التربية الإسلامية',
    'الحاسوب'
  ];

  for (const item of semesters) {
    await q(
      `INSERT INTO semesters(name)
       VALUES($1)
       ON CONFLICT(name) DO NOTHING`,
      [item]
    );
  }

  for (const item of grades) {
    await q(
      `INSERT INTO grades(name)
       VALUES($1)
       ON CONFLICT(name) DO NOTHING`,
      [item]
    );
  }

  for (const item of subjects) {
    await q(
      `INSERT INTO subjects(name)
       VALUES($1)
       ON CONFLICT(name) DO NOTHING`,
      [item]
    );
  }

  const settings = {
    site_title: 'شرح دروسي',
    welcome_title: 'تعلّم • افهم • اختبر نفسك',
    welcome_text:
      'مرحبًا بك في شرح دروسي. اختر الصف والمادة ثم اكتب اسم الدرس.',
    footer_text: 'شرح دروسي © 2026',
    site_enabled: 'true'
  };

  for (const [key, value] of Object.entries(settings)) {
    await q(
      `INSERT INTO settings(key,value)
       VALUES($1,$2)
       ON CONFLICT(key) DO NOTHING`,
      [key, value]
    );
  }
}

/* =========================
   TEST
========================= */

app.get('/api/test', async (_req, res) => {
  let database = false;

  try {
    if (pool) {
      await q('SELECT 1');
      database = true;
    }
  } catch (_) {}

  res.json({
    success: true,
    server: true,
    database,
    port: String(PORT)
  });
});

/* =========================
   ADMIN SETUP
========================= */

app.get(
  '/api/admin/setup-status',
  async (_req, res) => {
    try {
      const r =
        await q(
          'SELECT COUNT(*)::int n FROM admins'
        );

      res.json({
        success: true,
        setupRequired:
          r.rows[0].n === 0
      });

    } catch {
      jsonErr(
        res,
        500,
        'تعذر التحقق من حالة الإدارة.'
      );
    }
  }
);

app.post(
  '/api/admin/setup',
  async (req, res) => {

    const username =
      String(req.body.username || '').trim();

    const password =
      String(req.body.password || '');

    if (username.length < 3) {
      return jsonErr(
        res,
        400,
        'اسم المستخدم يجب أن يكون 3 أحرف على الأقل.'
      );
    }

    if (password.length < 6) {
      return jsonErr(
        res,
        400,
        'كلمة المرور يجب أن تكون 6 أحرف على الأقل.'
      );
    }

    try {

      const count =
        await q(
          'SELECT COUNT(*)::int n FROM admins'
        );

      if (count.rows[0].n > 0) {
        return jsonErr(
          res,
          409,
          'تم إنشاء حساب المدير الأول مسبقًا. استخدم تسجيل الدخول.'
        );
      }

      const hash =
        await bcrypt.hash(password, 12);

      const r =
        await q(
          `INSERT INTO admins(
            username,
            password_hash,
            can_manage_content,
            can_manage_admins,
            can_view_stats,
            can_manage_settings,
            is_owner
          )
          VALUES(
            $1,$2,true,true,true,true,true
          )
          RETURNING *`,
          [username, hash]
        );

      const admin = r.rows[0];
      const token =
        await newToken(admin.id);

      await log(
        admin.id,
        'إنشاء حساب المدير الأول',
        `اسم المستخدم: ${username}`
      );

      res.json({
        success: true,
        token,
        admin: publicAdmin(admin)
      });

    } catch (e) {

      jsonErr(
        res,
        500,
        'تعذر إنشاء حساب المدير.'
      );
    }
  }
);

/* =========================
   ADMIN LOGIN
========================= */

app.post(
  '/api/admin/login',
  async (req, res) => {

    const username =
      String(req.body.username || '').trim();

    const password =
      String(req.body.password || '');

    try {

      const r =
        await q(
          `SELECT *
           FROM admins
           WHERE LOWER(username)=LOWER($1)
           LIMIT 1`,
          [username]
        );

      const admin =
        r.rows[0];

      if (!admin || !admin.active) {
        return jsonErr(
          res,
          401,
          'اسم المستخدم أو كلمة المرور غير صحيحة.'
        );
      }

      const valid =
        await bcrypt.compare(
          password,
          admin.password_hash
        );

      if (!valid) {
        return jsonErr(
          res,
          401,
          'اسم المستخدم أو كلمة المرور غير صحيحة.'
        );
      }

      const token =
        await newToken(admin.id);

      await log(
        admin.id,
        'تسجيل الدخول'
      );

      res.json({
        success: true,
        token,
        admin: publicAdmin(admin)
      });

    } catch {
      jsonErr(
        res,
        500,
        'تعذر تسجيل الدخول.'
      );
    }
  }
);

/* =========================
   ADMIN ME
========================= */

app.get(
  '/api/admin/me',
  auth,
  (req, res) => {
    res.json({
      success: true,
      admin: publicAdmin(req.admin)
    });
  }
);

/* =========================
   LOGOUT
========================= */

app.post(
  '/api/admin/logout',
  auth,
  async (req, res) => {

    try {

      await q(
        'DELETE FROM admin_sessions WHERE token=$1',
        [req.get('x-admin-token')]
      );

      await log(
        req.admin.id,
        'تسجيل الخروج'
      );

    } catch (_) {}

    res.json({
      success: true
    });
  }
);

/* =========================
   CATALOG
========================= */

const tables = {
  semesters: 'semesters',
  grades: 'grades',
  subjects: 'subjects'
};

for (
  const [route, table]
  of Object.entries(tables)
) {

  app.get(
    '/api/admin/' + route,
    auth,
    async (_req, res) => {

      try {

        const r =
          await q(
            `SELECT id,name,enabled
             FROM ${table}
             ORDER BY id`
          );

        res.json({
          success: true,
          items: r.rows
        });

      } catch {
        jsonErr(
          res,
          500,
          'تعذر تحميل البيانات.'
        );
      }
    }
  );

  app.post(
    '/api/admin/' + route,
    auth,
    async (req, res) => {

      if (
        !perm(
          req,
          res,
          'can_manage_content'
        )
      ) return;

      const name =
        String(req.body.name || '').trim();

      if (!name) {
        return jsonErr(
          res,
          400,
          'اكتب الاسم.'
        );
      }

      try {

        const r =
          await q(
            `INSERT INTO ${table}(name)
             VALUES($1)
             RETURNING id,name,enabled`,
            [name]
          );

        await log(
          req.admin.id,
          'إضافة ' + route,
          'الاسم: ' + name
        );

        res.json({
          success: true,
          item: r.rows[0]
        });

      } catch {
        jsonErr(
          res,
          400,
          'هذا الاسم موجود بالفعل أو غير صالح.'
        );
      }
    }
  );

  app.put(
    '/api/admin/' + route + '/:id',
    auth,
    async (req, res) => {

      if (
        !perm(
          req,
          res,
          'can_manage_content'
        )
      ) return;

      try {

        const r =
          await q(
            `UPDATE ${table}
             SET name=$1,
                 enabled=$2
             WHERE id=$3
             RETURNING id,name,enabled`,
            [
              String(req.body.name || '').trim(),
              req.body.enabled !== false,
              Number(req.params.id)
            ]
          );

        if (!r.rows[0]) {
          return jsonErr(
            res,
            404,
            'العنصر غير موجود.'
          );
        }

        await log(
          req.admin.id,
          'تعديل ' + route,
          'المعرف: ' + req.params.id
        );

        res.json({
          success: true,
          item: r.rows[0]
        });

      } catch {
        jsonErr(
          res,
          400,
          'تعذر تعديل العنصر.'
        );
      }
    }
  );

  app.delete(
    '/api/admin/' + route + '/:id',
    auth,
    async (req, res) => {

      if (
        !perm(
          req,
          res,
          'can_manage_content'
        )
      ) return;

      try {

        await q(
          `DELETE FROM ${table}
           WHERE id=$1`,
          [Number(req.params.id)]
        );

        await log(
          req.admin.id,
          'حذف ' + route,
          'المعرف: ' + req.params.id
        );

        res.json({
          success: true
        });

      } catch {
        jsonErr(
          res,
          500,
          'تعذر حذف العنصر.'
        );
      }
    }
  );
}

/* =========================
   LESSONS
========================= */

app.get(
  '/api/admin/lessons',
  auth,
  async (req, res) => {

    if (
      !perm(
        req,
        res,
        'can_manage_content'
      )
    ) return;

    try {

      const r =
        await q(
          `SELECT
             id,
             semester,
             grade,
             subject,
             title,
             description,
             video_url,
             enabled,
             created_at,
             updated_at
           FROM lessons
           ORDER BY id DESC`
        );

      res.json({
        success: true,
        items: r.rows
      });

    } catch {
      jsonErr(
        res,
        500,
        'تعذر تحميل الدروس.'
      );
    }
  }
);

app.post(
  '/api/admin/lessons',
  auth,
  async (req, res) => {

    if (
      !perm(
        req,
        res,
        'can_manage_content'
      )
    ) return;

    const semester =
      String(req.body.semester || '');

    const grade =
      String(req.body.grade || '');

    const subject =
      String(req.body.subject || '');

    const title =
      String(req.body.title || '').trim();

    const description =
      String(req.body.description || '');

    const video_url =
      String(req.body.video_url || '');

    if (!title) {
      return jsonErr(
        res,
        400,
        'اكتب اسم الدرس.'
      );
    }

    try {

      const r =
        await q(
          `INSERT INTO lessons(
            semester,
            grade,
            subject,
            title,
            description,
            video_url
          )
          VALUES($1,$2,$3,$4,$5,$6)
          RETURNING *`,
          [
            semester,
            grade,
            subject,
            title,
            description,
            video_url
          ]
        );

      await log(
        req.admin.id,
        'إضافة درس',
        'الدرس: ' + title
      );

      res.json({
        success: true,
        item: r.rows[0]
      });

    } catch {
      jsonErr(
        res,
        500,
        'تعذر إضافة الدرس.'
      );
    }
  }
);

app.put(
  '/api/admin/lessons/:id',
  auth,
  async (req, res) => {

    if (
      !perm(
        req,
        res,
        'can_manage_content'
      )
    ) return;

    const title =
      String(req.body.title || '').trim();

    if (!title) {
      return jsonErr(
        res,
        400,
        'اكتب اسم الدرس.'
      );
    }

    try {

      const r =
        await q(
          `UPDATE lessons
           SET semester=$1,
               grade=$2,
               subject=$3,
               title=$4,
               description=$5,
               video_url=$6,
               enabled=$7,
               updated_at=NOW()
           WHERE id=$8
           RETURNING *`,
          [
            String(req.body.semester || ''),
            String(req.body.grade || ''),
            String(req.body.subject || ''),
            title,
            String(req.body.description || ''),
            String(req.body.video_url || ''),
            req.body.enabled !== false,
            Number(req.params.id)
          ]
        );

      if (!r.rows[0]) {
        return jsonErr(
          res,
          404,
          'الدرس غير موجود.'
        );
      }

      await log(
        req.admin.id,
        'تعديل درس',
        'الدرس: ' + title
      );

      res.json({
        success: true,
        item: r.rows[0]
      });

    } catch {
      jsonErr(
        res,
        500,
        'تعذر تعديل الدرس.'
      );
    }
  }
);

app.delete(
  '/api/admin/lessons/:id',
  auth,
  async (req, res) => {

    if (
      !perm(
        req,
        res,
        'can_manage_content'
      )
    ) return;

    try {

      await q(
        'DELETE FROM lessons WHERE id=$1',
        [Number(req.params.id)]
      );

      await log(
        req.admin.id,
        'حذف درس',
        'المعرف: ' + req.params.id
      );

      res.json({
        success: true
      });

    } catch {
      jsonErr(
        res,
        500,
        'تعذر حذف الدرس.'
      );
    }
  }
);

/* =========================
   ADMIN ACCOUNTS
========================= */

app.get(
  '/api/admin/accounts',
  auth,
  async (req, res) => {

    if (
      !perm(
        req,
        res,
        'can_manage_admins'
      )
    ) return;

    try {

      const r =
        await q(
          `SELECT
             id,
             username,
             active,
             can_manage_content,
             can_manage_admins,
             can_view_stats,
             can_manage_settings,
             is_owner,
             created_at
           FROM admins
           ORDER BY id`
        );

      res.json({
        success: true,
        items: r.rows
      });

    } catch {
      jsonErr(
        res,
        500,
        'تعذر تحميل حسابات الإداريين.'
      );
    }
  }
);

app.post(
  '/api/admin/accounts',
  auth,
  async (req, res) => {

    if (
      !perm(
        req,
        res,
        'can_manage_admins'
      )
    ) return;

    const username =
      String(req.body.username || '').trim();

    const password =
      String(req.body.password || '');

    if (username.length < 3) {
      return jsonErr(
        res,
        400,
        'اسم المستخدم قصير.'
      );
    }

    if (password.length < 6) {
      return jsonErr(
        res,
        400,
        'كلمة المرور يجب أن تكون 6 أحرف على الأقل.'
      );
    }

    try {

      const hash =
        await bcrypt.hash(
          password,
          12
        );

      const r =
        await q(
          `INSERT INTO admins(
            username,
            password_hash,
            can_manage_content,
            can_manage_admins,
            can_view_stats,
            can_manage_settings
          )
          VALUES($1,$2,$3,$4,$5,$6)
          RETURNING *`,
          [
            username,
            hash,
            req.body.can_manage_content === true,
            req.body.can_manage_admins === true,
            req.body.can_view_stats !== false,
            req.body.can_manage_settings === true
          ]
        );

      await log(
        req.admin.id,
        'إنشاء إداري',
        'اسم المستخدم: ' + username
      );

      res.json({
        success: true,
        admin: publicAdmin(r.rows[0])
      });

    } catch {
      jsonErr(
        res,
        400,
        'اسم المستخدم موجود بالفعل أو غير صالح.'
      );
    }
  }
);

app.put(
  '/api/admin/accounts/:id/permissions',
  auth,
  async (req, res) => {

    if (
      !perm(
        req,
        res,
        'can_manage_admins'
      )
    ) return;

    const id =
      Number(req.params.id);

    if (id === req.admin.id) {
      return jsonErr(
        res,
        400,
        'لا تعدل صلاحيات حسابك من هنا.'
      );
    }

    try {

      const r =
        await q(
          `UPDATE admins
           SET
             can_manage_content=$1,
             can_manage_admins=$2,
             can_view_stats=$3,
             can_manage_settings=$4
           WHERE id=$5
           AND is_owner=false
           RETURNING *`,
          [
            req.body.can_manage_content === true,
            req.body.can_manage_admins === true,
            req.body.can_view_stats !== false,
            req.body.can_manage_settings === true,
            id
          ]
        );

      if (!r.rows[0]) {
        return jsonErr(
          res,
          404,
          'الحساب غير موجود أو محمي.'
        );
      }

      await log(
        req.admin.id,
        'تعديل صلاحيات إداري',
        'المعرف: ' + id
      );

      res.json({
        success: true,
        admin: publicAdmin(r.rows[0])
      });

    } catch {
      jsonErr(
        res,
        500,
        'تعذر تعديل الصلاحيات.'
      );
    }
  }
);

app.put(
  '/api/admin/accounts/:id/password',
  auth,
  async (req, res) => {

    if (
      !perm(
        req,
        res,
        'can_manage_admins'
      )
    ) return;

    const id =
      Number(req.params.id);

    const password =
      String(
        req.body.new_password || ''
      );

    if (password.length < 6) {
      return jsonErr(
        res,
        400,
        'كلمة المرور يجب أن تكون 6 أحرف على الأقل.'
      );
    }

    try {

      const hash =
        await bcrypt.hash(
          password,
          12
        );

      const r =
        await q(
          `UPDATE admins
           SET password_hash=$1
           WHERE id=$2
           AND is_owner=false
           RETURNING id,username`,
          [hash, id]
        );

      if (!r.rows[0]) {
        return jsonErr(
          res,
          404,
          'الحساب غير موجود أو محمي.'
        );
      }

      await log(
        req.admin.id,
        'تغيير كلمة مرور إداري',
        'المستخدم: ' +
        r.rows[0].username
      );

      res.json({
        success: true
      });

    } catch {
      jsonErr(
        res,
        500,
        'تعذر تغيير كلمة المرور.'
      );
    }
  }
);

app.delete(
  '/api/admin/accounts/:id',
  auth,
  async (req, res) => {

    if (
      !perm(
        req,
        res,
        'can_manage_admins'
      )
    ) return;

    const id =
      Number(req.params.id);

    if (id === req.admin.id) {
      return jsonErr(
        res,
        400,
        'لا يمكنك حذف حسابك الحالي.'
      );
    }

    try {

      const r =
        await q(
          `DELETE FROM admins
           WHERE id=$1
           AND is_owner=false
           RETURNING username`,
          [id]
        );

      if (!r.rows[0]) {
        return jsonErr(
          res,
          404,
          'الحساب غير موجود أو محمي.'
        );
      }

      await log(
        req.admin.id,
        'حذف إداري',
        'المستخدم: ' +
        r.rows[0].username
      );

      res.json({
        success: true
      });

    } catch {
      jsonErr(
        res,
        500,
        'تعذر حذف الحساب.'
      );
    }
  }
);

/* =========================
   MY PASSWORD
========================= */

app.put(
  '/api/admin/password',
  auth,
  async (req, res) => {

    const password =
      String(
        req.body.new_password || ''
      );

    if (password.length < 6) {
      return jsonErr(
        res,
        400,
        'كلمة المرور يجب أن تكون 6 أحرف على الأقل.'
      );
    }

    try {

      const hash =
        await bcrypt.hash(
          password,
          12
        );

      await q(
        `UPDATE admins
         SET password_hash=$1
         WHERE id=$2`,
        [hash, req.admin.id]
      );

      await log(
        req.admin.id,
        'تغيير كلمة المرور'
      );

      res.json({
        success: true
      });

    } catch {
      jsonErr(
        res,
        500,
        'تعذر تغيير كلمة المرور.'
      );
    }
  }
);

/* =========================
   SETTINGS
========================= */

app.get(
  '/api/admin/settings',
  auth,
  async (req, res) => {

    if (
      !perm(
        req,
        res,
        'can_manage_settings'
      )
    ) return;

    try {

      const r =
        await q(
          'SELECT key,value FROM settings ORDER BY key'
        );

      const settings = {};

      for (const item of r.rows) {
        settings[item.key] =
          item.value;
      }

      res.json({
        success: true,
        settings
      });

    } catch {
      jsonErr(
        res,
        500,
        'تعذر تحميل الإعدادات.'
      );
    }
  }
);

app.put(
  '/api/admin/settings',
  auth,
  async (req, res) => {

    if (
      !perm(
        req,
        res,
        'can_manage_settings'
      )
    ) return;

    try {

      const allowed = [
        'site_title',
        'welcome_title',
        'welcome_text',
        'footer_text',
        'site_enabled'
      ];

      for (const key of allowed) {

        if (
          req.body[key] !== undefined
        ) {

          await q(
            `INSERT INTO settings(
              key,
              value
            )
            VALUES($1,$2)
            ON CONFLICT(key)
            DO UPDATE SET
              value=EXCLUDED.value`,
            [
              key,
              String(req.body[key])
            ]
          );

        }
      }

      await log(
        req.admin.id,
        'تعديل إعدادات الموقع'
      );

      res.json({
        success: true
      });

    } catch {
      jsonErr(
        res,
        500,
        'تعذر حفظ الإعدادات.'
      );
    }
  }
);

/* =========================
   STATS
========================= */

app.get(
  '/api/admin/stats',
  auth,
  async (req, res) => {

    if (
      !perm(
        req,
        res,
        'can_view_stats'
      )
    ) return;

    try {

      const [
        visitors,
        searches,
        lessons,
        admins,
        activity
      ] =
        await Promise.all([
          q(
            'SELECT COUNT(*)::int n FROM visits'
          ),
          q(
            'SELECT COUNT(*)::int n FROM searches'
          ),
          q(
            `SELECT COUNT(*)::int n
             FROM lessons
             WHERE enabled=true`
          ),
          q(
            'SELECT COUNT(*)::int n FROM admins'
          ),
          q(
            'SELECT COUNT(*)::int n FROM activity_logs'
          )
        ]);

      res.json({
        success: true,
        stats: {
          visitors:
            visitors.rows[0].n,
          searches:
            searches.rows[0].n,
          lessons:
            lessons.rows[0].n,
          admins:
            admins.rows[0].n,
          activity:
            activity.rows[0].n
        }
      });

    } catch {
      jsonErr(
        res,
        500,
        'تعذر تحميل الإحصائيات.'
      );
    }
  }
);

/* =========================
   ACTIVITY
========================= */

app.get(
  '/api/admin/activity',
  auth,
  async (req, res) => {

    if (
      !perm(
        req,
        res,
        'can_manage_admins'
      )
    ) return;

    const limit =
      Math.min(
        Math.max(
          Number(req.query.limit) || 200,
          1
        ),
        500
      );

    try {

      const r =
        await q(
          `SELECT
             l.id,
             l.action,
             l.details,
             l.created_at,
             a.username AS admin_username
           FROM activity_logs l
           LEFT JOIN admins a
             ON a.id=l.admin_id
           ORDER BY l.id DESC
           LIMIT $1`,
          [limit]
        );

      res.json({
        success: true,
        items: r.rows
      });

    } catch {
      jsonErr(
        res,
        500,
        'تعذر تحميل سجل التعديلات.'
      );
    }
  }
);

/* =========================
   PUBLIC SITE CONFIG
========================= */

app.get(
  '/api/site-config',
  async (_req, res) => {

    try {

      const r =
        await q(
          'SELECT key,value FROM settings'
        );

      const settings = {
        site_title:
          'شرح دروسي',
        welcome_title:
          'تعلّم • افهم • اختبر نفسك',
        welcome_text:
          'مرحبًا بك في شرح دروسي.',
        footer_text:
          'شرح دروسي © 2026',
        site_enabled:
          'true'
      };

      for (const item of r.rows) {
        settings[item.key] =
          item.value;
      }

      const [
        semesters,
        grades,
        subjects
      ] =
        await Promise.all([
          q(
            'SELECT id,name,enabled FROM semesters ORDER BY id'
          ),
          q(
            'SELECT id,name,enabled FROM grades ORDER BY id'
          ),
          q(
            'SELECT id,name,enabled FROM subjects ORDER BY id'
          )
        ]);

      res.json({
        success: true,
        settings,
        semesters:
          semesters.rows,
        grades:
          grades.rows,
        subjects:
          subjects.rows
      });

    } catch {
      jsonErr(
        res,
        500,
        'تعذر تحميل بيانات الموقع.'
      );
    }
  }
);

/* =========================
   PUBLIC LESSONS
========================= */

app.get(
  '/api/lessons',
  async (req, res) => {

    try {

      const params = [];
      const where = [
        'enabled=true'
      ];

      if (req.query.grade) {
        params.push(
          String(req.query.grade)
        );

        where.push(
          `grade=$${params.length}`
        );
      }

      if (req.query.subject) {
        params.push(
          String(req.query.subject)
        );

        where.push(
          `subject=$${params.length}`
        );
      }

      if (req.query.q) {
        params.push(
          '%' +
          String(req.query.q) +
          '%'
        );

        where.push(
          `title ILIKE $${params.length}`
        );
      }

      const r =
        await q(
          `SELECT
             id,
             semester,
             grade,
             subject,
             title,
             description,
             video_url,
             enabled
           FROM lessons
           WHERE ${where.join(' AND ')}
           ORDER BY id DESC
           LIMIT 100`,
          params
        );

      res.json({
        success: true,
        items: r.rows
      });

    } catch {
      jsonErr(
        res,
        500,
        'تعذر تحميل الدروس.'
      );
    }
  }
);

/* =========================
   VISITS
========================= */

app.post(
  '/api/visit',
  async (_req, res) => {

    try {
      await q(
        'INSERT INTO visits DEFAULT VALUES'
      );
    } catch (_) {}

    res.json({
      success: true
    });
  }
);

/* =========================
   WEB SEARCH
========================= */

app.get(
  '/api/search',
  async (req, res) => {

    const query =
      String(req.query.q || '').trim();

    const grade =
      String(req.query.grade || '');

    const subject =
      String(req.query.subject || '');

    if (!query) {
      return jsonErr(
        res,
        400,
        'اكتب اسم الدرس.'
      );
    }

    try {

      await q(
        `INSERT INTO searches(
          query,
          grade,
          subject
        )
        VALUES($1,$2,$3)`,
        [
          query,
          grade,
          subject
        ]
      );

      let web = [];

      try {

        const wiki =
          await axios.get(
            'https://ar.wikipedia.org/w/api.php',
            {
              params: {
                action:
                  'query',
                generator:
                  'search',
                gsrsearch:
                  `${subject ? subject + ' ' : ''}${query}`,
                gsrlimit: 8,
                prop:
                  'extracts|info',
                exintro: 1,
                explaintext: 1,
                inprop: 'url',
                format: 'json',
                origin: '*'
              },
              timeout: 10000
            }
          );

        web =
          Object.values(
            wiki.data?.query?.pages || {}
          ).map(
            page => ({
              title:
                page.title,
              snippet:
                page.extract || '',
              url:
                page.fullurl || ''
            })
          );

      } catch (_) {}

      res.json({
        success: true,
        web,
        results: web,
        summary:
          web[0]?.snippet || '',
        questions: []
      });

    } catch {
      jsonErr(
        res,
        500,
        'تعذر البحث الآن.'
      );
    }
  }
);

/* =========================
   YOUTUBE
========================= */

app.get(
  '/api/youtube-search',
  async (req, res) => {

    const search =
      String(req.query.q || '').trim();

    if (!search) {
      return jsonErr(
        res,
        400,
        'أدخل كلمة البحث.'
      );
    }

    const key =
      process.env.YOUTUBE_API_KEY;

    if (!key) {
      return res.json({
        success: true,
        items: []
      });
    }

    try {

      const result =
        await axios.get(
          'https://www.googleapis.com/youtube/v3/search',
          {
            params: {
              part: 'snippet',
              type: 'video',
              maxResults: 12,
              q: search,
              key
            },
            timeout: 10000
          }
        );

      const items =
        (result.data.items || [])
          .map(
            video => ({
              videoId:
                video.id?.videoId,
              title:
                video.snippet?.title,
              channel:
                video.snippet?.channelTitle,
              thumbnail:
                video.snippet?.thumbnails?.high?.url ||
                video.snippet?.thumbnails?.medium?.url
            })
          );

      res.json({
        success: true,
        items
      });

    } catch {
      jsonErr(
        res,
        500,
        'تعذر جلب فيديوهات YouTube.'
      );
    }
  }
);

/* =========================
   PAGES
========================= */

app.get(
  '/admin',
  (_req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        'admin.html'
      )
    );
  }
);

app.get(
  '/',
  (_req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        'index.html'
      )
    );
  }
);

app.use(
  express.static(__dirname)
);

/* =========================
   404
========================= */

app.use(
  (req, res) => {

    if (
      req.path.startsWith('/api/')
    ) {

      return res
        .status(404)
        .json({
          success: false,
          message:
            'API endpoint غير موجود.'
        });
    }

    res
      .status(404)
      .send(
        'الصفحة غير موجودة'
      );
  }
);

/* =========================
   START
========================= */

init()
  .then(
    () => {

      app.listen(
        PORT,
        () => {
          console.log(
            `شرح دروسي يعمل على المنفذ ${PORT}`
          );
        }
      );

    }
  )
  .catch(
    err => {

      console.error(err);

      app.listen(
        PORT,
        () => {
          console.log(
            `شرح دروسي يعمل على المنفذ ${PORT} بدون تهيئة قاعدة البيانات`
          );
        }
      );
    }
  );
