require("dotenv").config();

const express = require("express");
const axios = require("axios");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 3000;


/* =========================================
   Express
========================================= */

app.use(express.json({ limit: "1mb" }));
app.use(express.static(__dirname));


/* =========================================
   PostgreSQL
========================================= */

let pool = null;

if (process.env.DATABASE_URL) {

    pool = new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: {
            rejectUnauthorized: false
        },
        max: 5,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 10000
    });

    pool.on("error", (error) => {
        console.error("PostgreSQL error:", error.message);
    });

}


/* =========================================
   التحقق من قاعدة البيانات
========================================= */

function requireDatabase(req, res, next) {

    if (!pool) {

        return res.status(503).json({
            success: false,
            message: "قاعدة البيانات غير متصلة"
        });

    }

    next();
}


/* =========================================
   إنشاء الجداول
========================================= */

async function initDatabase() {

    if (!pool) {
        console.log("DATABASE_URL غير موجود محليًا.");
        return;
    }


    await pool.query(`
        CREATE TABLE IF NOT EXISTS admins (

            id SERIAL PRIMARY KEY,

            username VARCHAR(100)
                UNIQUE NOT NULL,

            password_hash TEXT NOT NULL,

            can_manage_lessons BOOLEAN
                NOT NULL DEFAULT TRUE,

            can_manage_admins BOOLEAN
                NOT NULL DEFAULT FALSE,

            can_view_stats BOOLEAN
                NOT NULL DEFAULT TRUE,

            created_at TIMESTAMPTZ
                NOT NULL DEFAULT NOW()

        );
    `);


    await pool.query(`
        CREATE TABLE IF NOT EXISTS admin_sessions (

            token TEXT PRIMARY KEY,

            admin_id INTEGER
                NOT NULL
                REFERENCES admins(id)
                ON DELETE CASCADE,

            expires_at TIMESTAMPTZ
                NOT NULL

        );
    `);


    await pool.query(`
        CREATE TABLE IF NOT EXISTS lessons (

            id SERIAL PRIMARY KEY,

            semester VARCHAR(100),

            grade VARCHAR(100),

            subject VARCHAR(150),

            title VARCHAR(300)
                NOT NULL,

            description TEXT,

            video_url TEXT,

            created_at TIMESTAMPTZ
                NOT NULL DEFAULT NOW()

        );
    `);


    await pool.query(`
        CREATE TABLE IF NOT EXISTS searches (

            id BIGSERIAL PRIMARY KEY,

            query TEXT NOT NULL,

            semester VARCHAR(100),

            grade VARCHAR(100),

            subject VARCHAR(150),

            created_at TIMESTAMPTZ
                NOT NULL DEFAULT NOW()

        );
    `);


    await pool.query(`
        CREATE TABLE IF NOT EXISTS visits (

            id BIGSERIAL PRIMARY KEY,

            visitor_id VARCHAR(120)
                UNIQUE NOT NULL,

            created_at TIMESTAMPTZ
                NOT NULL DEFAULT NOW()

        );
    `);


    console.log("PostgreSQL جاهز ✅");
}


/* =========================================
   الصفحة الرئيسية
========================================= */

app.get("/", (req, res) => {

    res.sendFile(
        __dirname + "/index.html"
    );

});


/* =========================================
   اختبار السيرفر
========================================= */

app.get("/api/test", async (req, res) => {

    let database = false;

    if (pool) {

        try {

            await pool.query("SELECT NOW()");
            database = true;

        } catch (error) {

            console.error(
                "Database test error:",
                error.message
            );

        }

    }

    res.json({

        success: true,

        server: true,

        database: database,

        port: PORT

    });

});


/* =========================================
   اختبار الاتصال
========================================= */

app.get("/api/hello", (req, res) => {

    res.json({

        success: true,

        message:
            "شرح دروسي متصل بالسيرفر 🚀"

    });

});


/* =========================================
   استقبال البحث
========================================= */

app.get("/api/search", async (req, res) => {

    const query =
        String(req.query.q || "").trim();

    const semester =
        String(req.query.semester || "").trim();

    const grade =
        String(req.query.grade || "").trim();

    const subject =
        String(req.query.subject || "").trim();


    if (!query) {

        return res.status(400).json({

            success: false,

            message:
                "اكتب اسم الدرس"

        });

    }


    if (pool) {

        try {

            await pool.query(

                `
                INSERT INTO searches
                (
                    query,
                    semester,
                    grade,
                    subject
                )

                VALUES
                ($1,$2,$3,$4)
                `,

                [
                    query,
                    semester,
                    grade,
                    subject
                ]

            );

        } catch (error) {

            console.error(
                "Search log error:",
                error.message
            );

        }

    }


    res.json({

        success: true,

        query: query

    });

});


/* =========================================
   YouTube
========================================= */

app.get(
    "/api/youtube-search",
    async (req, res) => {

        const query =
            String(req.query.q || "").trim();


        if (!query) {

            return res.status(400).json({

                success: false,

                message:
                    "اكتب اسم الدرس"

            });

        }


        const apiKey =
            process.env.YOUTUBE_API_KEY;


        if (!apiKey) {

            return res.status(500).json({

                success: false,

                message:
                    "مفتاح YouTube API غير موجود"

            });

        }


        try {

            const response =
                await axios.get(
                    "https://www.googleapis.com/youtube/v3/search",
                    {

                        params: {

                            part: "snippet",

                            type: "video",

                            maxResults: 12,

                            q: query,

                            key: apiKey

                        },

                        timeout: 15000

                    }
                );


            res.json({

                success: true,

                items:
                    response.data.items || []

            });

        } catch (error) {

            console.error(
                "YouTube API error:",
                error.response?.data ||
                error.message
            );


            res.status(500).json({

                success: false,

                message:
                    error.response?.data?.error?.message ||
                    "تعذر البحث في YouTube"

            });

        }

    }
);


/* =========================================
   إنشاء جلسة أدمن
========================================= */

async function createSession(adminId) {

    const token =
        crypto
        .randomBytes(48)
        .toString("hex");


    await pool.query(

        `
        INSERT INTO admin_sessions
        (
            token,
            admin_id,
            expires_at
        )

        VALUES
        (
            $1,
            $2,
            NOW() + INTERVAL '24 hours'
        )
        `,

        [
            token,
            adminId
        ]

    );


    return token;
}


/* =========================================
   الحصول على الأدمن الحالي
========================================= */

async function getAdminFromRequest(req) {

    if (!pool) {
        return null;
    }


    let token =
        req.headers["x-admin-token"] || "";


    if (!token) {

        const auth =
            req.headers.authorization || "";


        if (
            auth
            .toLowerCase()
            .startsWith("bearer ")
        ) {

            token =
                auth.slice(7).trim();

        }

    }


    if (!token) {
        return null;
    }


    const result =
        await pool.query(

            `
            SELECT

                a.id,
                a.username,
                a.can_manage_lessons,
                a.can_manage_admins,
                a.can_view_stats

            FROM admin_sessions s

            JOIN admins a
                ON a.id = s.admin_id

            WHERE
                s.token = $1

            AND
                s.expires_at > NOW()

            LIMIT 1
            `,

            [token]

        );


    return result.rows[0] || null;
}


/* =========================================
   حماية الأدمن
========================================= */

async function requireAdmin(req, res, next) {

    try {

        const admin =
            await getAdminFromRequest(req);


        if (!admin) {

            return res.status(401).json({

                success: false,

                message:
                    "يجب تسجيل الدخول للأدمن"

            });

        }


        req.admin = admin;

        next();

    } catch (error) {

        console.error(
            "Admin auth error:",
            error.message
        );


        res.status(500).json({

            success: false,

            message:
                "حدث خطأ أثناء التحقق"

        });

    }

}


/* =========================================
   إنشاء أول حساب أدمن
========================================= */

app.post(
    "/api/admin/setup",
    requireDatabase,
    async (req, res) => {

        try {

            const username =
                String(
                    req.body.username || ""
                ).trim();


            const password =
                String(
                    req.body.password || ""
                );


            if (
                username.length < 3 ||
                password.length < 8
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "اسم المستخدم 3 أحرف على الأقل وكلمة المرور 8 أحرف على الأقل"

                });

            }


            const countResult =
                await pool.query(
                    "SELECT COUNT(*)::int AS count FROM admins"
                );


            if (
                Number(
                    countResult.rows[0].count
                ) > 0
            ) {

                return res.status(403).json({

                    success: false,

                    message:
                        "تم إنشاء حساب الأدمن الأول مسبقًا"

                });

            }


            const passwordHash =
                await bcrypt.hash(
                    password,
                    12
                );


            const result =
                await pool.query(

                    `
                    INSERT INTO admins
                    (
                        username,
                        password_hash,
                        can_manage_lessons,
                        can_manage_admins,
                        can_view_stats
                    )

                    VALUES
                    ($1,$2,TRUE,TRUE,TRUE)

                    RETURNING id, username
                    `,

                    [
                        username,
                        passwordHash
                    ]

                );


            const admin =
                result.rows[0];


            const token =
                await createSession(
                    admin.id
                );


            res.status(201).json({

                success: true,

                token: token,

                admin: admin

            });

        } catch (error) {

            console.error(
                "Setup error:",
                error.message
            );


            res.status(500).json({

                success: false,

                message:
                    "تعذر إنشاء حساب الأدمن"

            });

        }

    }
);


/* =========================================
   تسجيل دخول الأدمن
========================================= */

app.post(
    "/api/admin/login",
    requireDatabase,
    async (req, res) => {

        try {

            const username =
                String(
                    req.body.username || ""
                ).trim();


            const password =
                String(
                    req.body.password || ""
                );


            const result =
                await pool.query(

                    `
                    SELECT *

                    FROM admins

                    WHERE
                        LOWER(username)
                        =
                        LOWER($1)

                    LIMIT 1
                    `,

                    [username]

                );


            const admin =
                result.rows[0];


            if (!admin) {

                return res.status(401).json({

                    success: false,

                    message:
                        "اسم المستخدم أو كلمة المرور غير صحيحة"

                });

            }


            const valid =
                await bcrypt.compare(
                    password,
                    admin.password_hash
                );


            if (!valid) {

                return res.status(401).json({

                    success: false,

                    message:
                        "اسم المستخدم أو كلمة المرور غير صحيحة"

                });

            }


            const token =
                await createSession(
                    admin.id
                );


            res.json({

                success: true,

                token: token,

                admin: {

                    id:
                        admin.id,

                    username:
                        admin.username,

                    can_manage_lessons:
                        admin.can_manage_lessons,

                    can_manage_admins:
                        admin.can_manage_admins,

                    can_view_stats:
                        admin.can_view_stats

                }

            });

        } catch (error) {

            console.error(
                "Login error:",
                error.message
            );


            res.status(500).json({

                success: false,

                message:
                    "تعذر تسجيل الدخول"

            });

        }

    }
);


/* =========================================
   الأدمن الحالي
========================================= */

app.get(
    "/api/admin/me",
    requireDatabase,
    requireAdmin,
    (req, res) => {

        res.json({

            success: true,

            admin:
                req.admin

        });

    }
);


/* =========================================
   تسجيل الخروج
========================================= */

app.post(
    "/api/admin/logout",
    requireDatabase,
    requireAdmin,
    async (req, res) => {

        const token =
            req.headers["x-admin-token"] || "";


        if (token) {

            await pool.query(

                `
                DELETE FROM admin_sessions
                WHERE token = $1
                `,

                [token]

            );

        }


        res.json({

            success: true

        });

    }
);


/* =========================================
   إضافة درس
========================================= */

app.post(
    "/api/admin/lessons",
    requireDatabase,
    requireAdmin,
    async (req, res) => {

        if (!req.admin.can_manage_lessons) {

            return res.status(403).json({

                success: false,

                message:
                    "ليس لديك صلاحية إدارة الدروس"

            });

        }


        try {

            const semester =
                String(
                    req.body.semester || ""
                ).trim();


            const grade =
                String(
                    req.body.grade || ""
                ).trim();


            const subject =
                String(
                    req.body.subject || ""
                ).trim();


            const title =
                String(
                    req.body.title || ""
                ).trim();


            const description =
                String(
                    req.body.description || ""
                ).trim();


            const videoUrl =
                String(
                    req.body.video_url || ""
                ).trim();


            if (!title) {

                return res.status(400).json({

                    success: false,

                    message:
                        "اسم الدرس مطلوب"

                });

            }


            const result =
                await pool.query(

                    `
                    INSERT INTO lessons
                    (
                        semester,
                        grade,
                        subject,
                        title,
                        description,
                        video_url
                    )

                    VALUES
                    ($1,$2,$3,$4,$5,$6)

                    RETURNING *
                    `,

                    [
                        semester,
                        grade,
                        subject,
                        title,
                        description,
                        videoUrl
                    ]

                );


            res.status(201).json({

                success: true,

                lesson:
                    result.rows[0]

            });

        } catch (error) {

            console.error(
                "Add lesson error:",
                error.message
            );


            res.status(500).json({

                success: false,

                message:
                    "تعذر إضافة الدرس"

            });

        }

    }
);


/* =========================================
   عرض الدروس
========================================= */

app.get(
    "/api/lessons",
    requireDatabase,
    async (req, res) => {

        try {

            const semester =
                String(
                    req.query.semester || ""
                ).trim();


            const grade =
                String(
                    req.query.grade || ""
                ).trim();


            const subject =
                String(
                    req.query.subject || ""
                ).trim();


            const result =
                await pool.query(

                    `
                    SELECT *

                    FROM lessons

                    WHERE
                        ($1 = '' OR semester = $1)

                    AND
                        ($2 = '' OR grade = $2)

                    AND
                        ($3 = '' OR subject = $3)

                    ORDER BY id DESC
                    `,

                    [
                        semester,
                        grade,
                        subject
                    ]

                );


            res.json({

                success: true,

                items:
                    result.rows

            });

        } catch (error) {

            res.status(500).json({

                success: false,

                message:
                    "تعذر تحميل الدروس"

            });

        }

    }
);


/* =========================================
   حذف درس
========================================= */

app.delete(
    "/api/admin/lessons/:id",
    requireDatabase,
    requireAdmin,
    async (req, res) => {

        if (!req.admin.can_manage_lessons) {

            return res.status(403).json({

                success: false,

                message:
                    "ليس لديك صلاحية إدارة الدروس"

            });

        }


        const id =
            Number(
                req.params.id
            );


        if (!Number.isInteger(id)) {

            return res.status(400).json({

                success: false,

                message:
                    "رقم الدرس غير صحيح"

            });

        }


        const result =
            await pool.query(

                `
                DELETE FROM lessons
                WHERE id = $1
                `,

                [id]

            );


        res.json({

            success: true,

            deleted:
                result.rowCount > 0

        });

    }
);


/* =========================================
   الإحصائيات
========================================= */

app.get(
    "/api/admin/stats",
    requireDatabase,
    requireAdmin,
    async (req, res) => {

        if (!req.admin.can_view_stats) {

            return res.status(403).json({

                success: false,

                message:
                    "ليس لديك صلاحية الإحصائيات"

            });

        }


        try {

            const [
                admins,
                lessons,
                searches,
                visitors
            ] = await Promise.all([

                pool.query(
                    "SELECT COUNT(*)::int AS count FROM admins"
                ),

                pool.query(
                    "SELECT COUNT(*)::int AS count FROM lessons"
                ),

                pool.query(
                    "SELECT COUNT(*)::int AS count FROM searches"
                ),

                pool.query(
                    "SELECT COUNT(*)::int AS count FROM visits"
                )

            ]);


            res.json({

                success: true,

                stats: {

                    admins:
                        admins.rows[0].count,

                    lessons:
                        lessons.rows[0].count,

                    searches:
                        searches.rows[0].count,

                    visitors:
                        visitors.rows[0].count

                }

            });

        } catch (error) {

            res.status(500).json({

                success: false,

                message:
                    "تعذر تحميل الإحصائيات"

            });

        }

    }
);


/* =========================================
   تسجيل زائر
========================================= */

app.post(
    "/api/visit",
    requireDatabase,
    async (req, res) => {

        const visitorId =
            String(
                req.body.visitor_id || ""
            ).trim();


        if (!visitorId) {

            return res.status(400).json({

                success: false,

                message:
                    "visitor_id مطلوب"

            });

        }


        try {

            await pool.query(

                `
                INSERT INTO visits
                (
                    visitor_id
                )

                VALUES ($1)

                ON CONFLICT(visitor_id)
                DO NOTHING
                `,

                [visitorId]

            );


            res.json({

                success: true

            });

        } catch (error) {

            res.status(500).json({

                success: false,

                message:
                    "تعذر تسجيل الزيارة"

            });

        }

    }
);


/* =========================================
   إنشاء حساب أدمن إضافي
========================================= */

app.post(
    "/api/admin/accounts",
    requireDatabase,
    requireAdmin,
    async (req, res) => {

        if (!req.admin.can_manage_admins) {

            return res.status(403).json({

                success: false,

                message:
                    "ليس لديك صلاحية إدارة الحسابات"

            });

        }


        try {

            const username =
                String(
                    req.body.username || ""
                ).trim();


            const password =
                String(
                    req.body.password || ""
                );


            const canManageLessons =
                Boolean(
                    req.body.can_manage_lessons
                );


            const canManageAdmins =
                Boolean(
                    req.body.can_manage_admins
                );


            const canViewStats =
                req.body.can_view_stats !== false;


            if (
                username.length < 3 ||
                password.length < 8
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "بيانات الحساب غير صحيحة"

                });

            }


            const hash =
                await bcrypt.hash(
                    password,
                    12
                );


            const result =
                await pool.query(

                    `
                    INSERT INTO admins
                    (
                        username,
                        password_hash,
                        can_manage_lessons,
                        can_manage_admins,
                        can_view_stats
                    )

                    VALUES
                    ($1,$2,$3,$4,$5)

                    RETURNING
                        id,
                        username,
                        can_manage_lessons,
                        can_manage_admins,
                        can_view_stats
                    `,

                    [
                        username,
                        hash,
                        canManageLessons,
                        canManageAdmins,
                        canViewStats
                    ]

                );


            res.status(201).json({

                success: true,

                admin:
                    result.rows[0]

            });

        } catch (error) {

            if (error.code === "23505") {

                return res.status(409).json({

                    success: false,

                    message:
                        "اسم المستخدم مستخدم بالفعل"

                });

            }


            res.status(500).json({

                success: false,

                message:
                    "تعذر إنشاء الحساب"

            });

        }

    }
);


/* =========================================
   عرض حسابات الأدمن
========================================= */

app.get(
    "/api/admin/accounts",
    requireDatabase,
    requireAdmin,
    async (req, res) => {

        if (!req.admin.can_manage_admins) {

            return res.status(403).json({

                success: false,

                message:
                    "ليس لديك صلاحية عرض الحسابات"

            });

        }


        const result =
            await pool.query(

                `
                SELECT
                    id,
                    username,
                    can_manage_lessons,
                    can_manage_admins,
                    can_view_stats,
                    created_at

                FROM admins

                ORDER BY id DESC
                `

            );


        res.json({

            success: true,

            items:
                result.rows

        });

    }
);


/* =========================================
   حذف حساب أدمن
========================================= */

app.delete(
    "/api/admin/accounts/:id",
    requireDatabase,
    requireAdmin,
    async (req, res) => {

        if (!req.admin.can_manage_admins) {

            return res.status(403).json({

                success: false,

                message:
                    "ليس لديك صلاحية حذف الحسابات"

            });

        }


        const id =
            Number(
                req.params.id
            );


        if (!Number.isInteger(id)) {

            return res.status(400).json({

                success: false,

                message:
                    "رقم الحساب غير صحيح"

            });

        }


        if (id === req.admin.id) {

            return res.status(400).json({

                success: false,

                message:
                    "لا يمكنك حذف حسابك الحالي"

            });

        }


        const count =
            await pool.query(
                "SELECT COUNT(*)::int AS count FROM admins"
            );


        if (
            Number(
                count.rows[0].count
            ) <= 1
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "يجب أن يبقى حساب أدمن واحد على الأقل"

            });

        }


        await pool.query(

            `
            DELETE FROM admins
            WHERE id = $1
            `,

            [id]

        );


        res.json({

            success: true

        });

    }
);


/* =========================================
   تغيير كلمة المرور
========================================= */

app.put(
    "/api/admin/password",
    requireDatabase,
    requireAdmin,
    async (req, res) => {

        const newPassword =
            String(
                req.body.new_password || ""
            );


        if (newPassword.length < 8) {

            return res.status(400).json({

                success: false,

                message:
                    "كلمة المرور يجب أن تكون 8 أحرف على الأقل"

            });

        }


        const hash =
            await bcrypt.hash(
                newPassword,
                12
            );


        await pool.query(

            `
            UPDATE admins

            SET password_hash = $1

            WHERE id = $2
            `,

            [
                hash,
                req.admin.id
            ]

        );


        res.json({

            success: true,

            message:
                "تم تغيير كلمة المرور"

        });

    }
);


/* =========================================
   بدء السيرفر
========================================= */

async function startServer() {

    try {

        if (pool) {

            await initDatabase();

        }


        app.listen(
            PORT,
            "0.0.0.0",
            () => {

                console.log(
                    `شرح دروسي يعمل على المنفذ ${PORT}`
                );

                console.log(
                    `Local: http://localhost:${PORT}`
                );

                console.log(
                    pool
                        ? "PostgreSQL: Connected ✅"
                        : "PostgreSQL: Not configured locally"
                );

            }
        );

    } catch (error) {

        console.error(
            "Startup error:",
            error
        );

        process.exit(1);

    }

}


startServer();