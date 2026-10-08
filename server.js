const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const axios = require('axios');
require('dotenv').config();

const { Pool } = require('pg');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DATABASE_URL = process.env.DATABASE_URL || '';

const pool = DATABASE_URL
    ? new Pool({
        connectionString: DATABASE_URL,
        ssl: DATABASE_URL.includes('localhost')
            ? false
            : { rejectUnauthorized: false }
    })
    : null;


/* =========================================================
   MIDDLEWARE
========================================================= */

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));


/* =========================================================
   DATABASE
========================================================= */

function requireDatabase(req, res, next) {
    if (!pool) {
        return res.status(503).json({
            success: false,
            message: 'قاعدة البيانات غير متصلة'
        });
    }

    next();
}


async function initDatabase() {

    if (!pool) return;

    await pool.query(`
        CREATE TABLE IF NOT EXISTS admins (
            id SERIAL PRIMARY KEY,
            username VARCHAR(100) UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,

            can_manage_lessons BOOLEAN NOT NULL DEFAULT TRUE,
            can_manage_admins BOOLEAN NOT NULL DEFAULT FALSE,
            can_view_stats BOOLEAN NOT NULL DEFAULT FALSE,
            can_manage_catalog BOOLEAN NOT NULL DEFAULT TRUE,
            can_manage_settings BOOLEAN NOT NULL DEFAULT FALSE,
            can_view_activity BOOLEAN NOT NULL DEFAULT FALSE,

            is_owner BOOLEAN NOT NULL DEFAULT FALSE,

            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        )
    `);


    await pool.query(`
        CREATE TABLE IF NOT EXISTS admin_sessions (
            token TEXT PRIMARY KEY,
            admin_id INTEGER NOT NULL
                REFERENCES admins(id)
                ON DELETE CASCADE,

            expires_at TIMESTAMP NOT NULL,

            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        )
    `);


    await pool.query(`
        CREATE TABLE IF NOT EXISTS catalog_items (
            id SERIAL PRIMARY KEY,

            type VARCHAR(30) NOT NULL,

            name VARCHAR(255) NOT NULL,

            parent_id INTEGER NULL
                REFERENCES catalog_items(id)
                ON DELETE CASCADE,

            enabled BOOLEAN NOT NULL DEFAULT TRUE,

            created_at TIMESTAMP NOT NULL DEFAULT NOW(),

            updated_at TIMESTAMP NOT NULL DEFAULT NOW()
        )
    `);


    await pool.query(`
        CREATE TABLE IF NOT EXISTS lessons (
            id SERIAL PRIMARY KEY,

            semester VARCHAR(100),

            grade VARCHAR(255),

            subject VARCHAR(255),

            title VARCHAR(500) NOT NULL,

            description TEXT DEFAULT '',

            summary TEXT DEFAULT '',

            video_url TEXT DEFAULT '',

            enabled BOOLEAN NOT NULL DEFAULT TRUE,

            created_at TIMESTAMP NOT NULL DEFAULT NOW(),

            updated_at TIMESTAMP NOT NULL DEFAULT NOW()
        )
    `);


    await pool.query(`
        CREATE TABLE IF NOT EXISTS questions (
            id SERIAL PRIMARY KEY,

            lesson_id INTEGER NULL
                REFERENCES lessons(id)
                ON DELETE CASCADE,

            question TEXT NOT NULL,

            options JSONB NOT NULL
                DEFAULT '[]'::jsonb,

            correct_answer INTEGER NOT NULL
                DEFAULT 0,

            explanation TEXT DEFAULT '',

            enabled BOOLEAN NOT NULL DEFAULT TRUE,

            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        )
    `);


    await pool.query(`
        CREATE TABLE IF NOT EXISTS site_settings (
            key VARCHAR(100) PRIMARY KEY,

            value TEXT DEFAULT ''
        )
    `);


    await pool.query(`
        CREATE TABLE IF NOT EXISTS activity_logs (
            id SERIAL PRIMARY KEY,

            admin_id INTEGER NULL
                REFERENCES admins(id)
                ON DELETE SET NULL,

            action VARCHAR(255) NOT NULL,

            entity_type VARCHAR(100)
                DEFAULT '',

            entity_id INTEGER NULL,

            details TEXT DEFAULT '',

            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        )
    `);


    await pool.query(`
        CREATE TABLE IF NOT EXISTS app_stats (
            id INTEGER PRIMARY KEY DEFAULT 1,

            visits INTEGER NOT NULL DEFAULT 0,

            searches INTEGER NOT NULL DEFAULT 0,

            updated_at TIMESTAMP NOT NULL DEFAULT NOW()
        )
    `);


    await pool.query(`
        INSERT INTO app_stats (id)
        VALUES (1)

        ON CONFLICT (id)
        DO NOTHING
    `);


    const settings = [

        ['site_name', 'شرح دروسي'],

        ['site_title', 'شرح دروسي'],

        ['welcome_title', 'أهلاً بك في شرح دروسي'],

        ['welcome_text', 'تعلّم • افهم • اختبر نفسك'],

        ['search_placeholder', 'اكتب اسم الدرس الذي تريد البحث عنه'],

        ['footer_text', '© 2026 شرح دروسي'],

        ['theme_color', '#1677ff'],

        ['youtube_enabled', 'true'],

        ['web_enabled', 'true'],

        ['quiz_enabled', 'true'],

        ['general_info_enabled', 'true'],

        ['site_enabled', 'true']
    ];


    for (const [key, value] of settings) {

        await pool.query(`
            INSERT INTO site_settings
            (key, value)

            VALUES
            ($1, $2)

            ON CONFLICT (key)
            DO NOTHING
        `, [
            key,
            value
        ]);
    }


    console.log('PostgreSQL جاهز');
}


async function cleanupSessions() {

    if (!pool) return;

    await pool.query(`
        DELETE FROM admin_sessions
        WHERE expires_at <= NOW()
    `);
}


/* =========================================================
   SESSIONS
========================================================= */

async function createSession(adminId) {

    const token =
        crypto.randomBytes(48).toString('hex');


    await pool.query(`
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
    `, [
        token,
        adminId
    ]);


    return token;
}


/* =========================================================
   ADMIN HELPERS
========================================================= */

function safeAdmin(admin) {

    if (!admin) return null;


    return {

        id: admin.id,

        username: admin.username,

        can_manage_lessons:
            Boolean(
                admin.can_manage_lessons
            ),

        can_manage_admins:
            Boolean(
                admin.can_manage_admins
            ),

        can_view_stats:
            Boolean(
                admin.can_view_stats
            ),

        can_manage_catalog:
            Boolean(
                admin.can_manage_catalog
            ),

        can_manage_settings:
            Boolean(
                admin.can_manage_settings
            ),

        can_view_activity:
            Boolean(
                admin.can_view_activity
            ),

        can_manage_content:
            Boolean(
                admin.can_manage_lessons
            )
            ||
            Boolean(
                admin.can_manage_catalog
            ),

        is_owner:
            Boolean(
                admin.is_owner
            )
    };
}


function safeAdminAccount(admin) {

    return {

        id: admin.id,

        username: admin.username,

        can_manage_content:
            Boolean(
                admin.can_manage_lessons
            )
            ||
            Boolean(
                admin.can_manage_catalog
            ),

        can_manage_lessons:
            Boolean(
                admin.can_manage_lessons
            ),

        can_manage_admins:
            Boolean(
                admin.can_manage_admins
            ),

        can_view_stats:
            Boolean(
                admin.can_view_stats
            ),

        can_manage_catalog:
            Boolean(
                admin.can_manage_catalog
            ),

        can_manage_settings:
            Boolean(
                admin.can_manage_settings
            ),

        can_view_activity:
            Boolean(
                admin.can_view_activity
            ),

        is_owner:
            Boolean(
                admin.is_owner
            ),

        created_at:
            admin.created_at
    };
}


/* =========================================================
   AUTH
========================================================= */

async function getAdminFromRequest(req) {

    if (!pool) return null;


    let token =
        String(
            req.headers['x-admin-token'] || ''
        ).trim();


    if (!token) {

        const authorization =
            String(
                req.headers.authorization || ''
            );


        if (
            authorization
                .toLowerCase()
                .startsWith('bearer ')
        ) {

            token =
                authorization
                    .slice(7)
                    .trim();
        }
    }


    if (!token) return null;


    const result =
        await pool.query(`
            SELECT

                a.id,

                a.username,

                a.can_manage_lessons,

                a.can_manage_admins,

                a.can_view_stats,

                a.can_manage_catalog,

                a.can_manage_settings,

                a.can_view_activity,

                a.is_owner

            FROM admin_sessions s

            JOIN admins a
                ON a.id = s.admin_id

            WHERE
                s.token = $1

                AND s.expires_at > NOW()

            LIMIT 1
        `, [
            token
        ]);


    return (
        result.rows[0]
        ||
        null
    );
}


async function requireAdmin(
    req,
    res,
    next
) {

    try {

        const admin =
            await getAdminFromRequest(req);


        if (!admin) {

            return res.status(401).json({
                success: false,
                message:
                    'يجب تسجيل الدخول للأدمن'
            });
        }


        req.admin = admin;

        next();

    } catch (error) {

        console.error(error);

        res.status(500).json({
            success: false,
            message:
                'حدث خطأ أثناء التحقق'
        });
    }
}


function requirePermission(
    permission
) {

    return (
        req,
        res,
        next
    ) => {

        if (!req.admin) {

            return res.status(401).json({
                success: false,
                message:
                    'يجب تسجيل الدخول للأدمن'
            });
        }


        if (
            req.admin.is_owner
            ||
            req.admin[permission]
        ) {

            return next();
        }


        return res.status(403).json({
            success: false,
            message:
                'ليس لديك صلاحية لهذا الإجراء'
        });
    };
}


/* =========================================================
   ACTIVITY LOG
========================================================= */

async function logActivity(
    admin,
    action,
    entityType = '',
    entityId = null,
    details = ''
) {

    if (!pool) return;


    try {

        await pool.query(`
            INSERT INTO activity_logs
            (
                admin_id,
                action,
                entity_type,
                entity_id,
                details
            )

            VALUES
            (
                $1,
                $2,
                $3,
                $4,
                $5
            )
        `, [
            admin?.id || null,
            action,
            entityType,
            entityId,
            details
        ]);

    } catch (error) {

        console.error(
            'Activity log error:',
            error.message
        );
    }
}


/* =========================================================
   PAGES
========================================================= */

app.get(
    '/',
    (req, res) => {

        res.sendFile(
            path.join(
                __dirname,
                'index.html'
            )
        );
    }
);


app.get(
    '/admin',
    (req, res) => {

        res.sendFile(
            path.join(
                __dirname,
                'admin.html'
            )
        );
    }
);


app.get(
    '/admin.html',
    (req, res) => {

        res.sendFile(
            path.join(
                __dirname,
                'admin.html'
            )
        );
    }
);


/* =========================================================
   TEST
========================================================= */

app.get(
    '/api/test',
    requireDatabase,
    async (req, res) => {

        try {

            await pool.query(
                'SELECT 1'
            );


            res.json({

                success: true,

                server: true,

                database: true,

                port: String(PORT)

            });

        } catch (error) {

            console.error(error);

            res.status(500).json({

                success: false,

                server: true,

                database: false,

                port: String(PORT)

            });
        }
    }
);


/* =========================================================
   SETUP STATUS
========================================================= */

app.get(
    '/api/admin/setup-status',
    requireDatabase,
    async (req, res) => {

        try {

            const result =
                await pool.query(`
                    SELECT
                        COUNT(*)::int AS count
                    FROM admins
                `);


            res.json({

                success: true,

                setupRequired:
                    Number(
                        result.rows[0].count
                    ) === 0

            });

        } catch (error) {

            console.error(error);

            res.status(500).json({

                success: false,

                message:
                    'تعذر التحقق من حالة الحساب'

            });
        }
    }
);


/* =========================================================
   TEMPORARY RECOVERY PAGE
========================================================= */

app.get(
    '/admin-recover',
    (req, res) => {

        res.send(`

<!DOCTYPE html>

<html
    lang="ar"
    dir="rtl"
>

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width,initial-scale=1.0"
>

<title>
استعادة حساب الأدمن
</title>

<style>

body{
    margin:0;
    min-height:100vh;
    display:flex;
    align-items:center;
    justify-content:center;
    background:#080b12;
    color:#fff;
    font-family:Arial,Tahoma,sans-serif;
}

.box{
    width:min(450px,92%);
    background:#111827;
    border:1px solid #263247;
    border-radius:20px;
    padding:28px;
    box-shadow:0 20px 60px rgba(0,0,0,.4);
}

h1{
    margin-top:0;
}

p{
    color:#9ca8ba;
    line-height:1.8;
}

label{
    display:block;
    margin:15px 0 7px;
}

input{
    width:100%;
    box-sizing:border-box;
    padding:14px;
    border-radius:12px;
    border:1px solid #334155;
    background:#0b1220;
    color:#fff;
    outline:none;
}

button{
    width:100%;
    margin-top:20px;
    padding:14px;
    border:0;
    border-radius:12px;
    background:#1677ff;
    color:#fff;
    font-size:16px;
    font-weight:bold;
    cursor:pointer;
}

#msg{
    margin-top:15px;
    line-height:1.8;
}

</style>

</head>

<body>

<div class="box">

<h1>
🔐 استعادة حساب الأدمن
</h1>

<p>
هذه الصفحة مؤقتة لاستعادة حساب الإدارة.
</p>

<label>
رمز الاستعادة
</label>

<input
    id="code"
    type="password"
>

<label>
اسم المستخدم الجديد
</label>

<input
    id="username"
>

<label>
كلمة المرور الجديدة
</label>

<input
    id="password"
    type="password"
>

<button
    onclick="recover()"
>
استعادة الحساب
</button>

<div id="msg"></div>

</div>


<script>

async function recover(){

    const code =
        document
        .getElementById('code')
        .value
        .trim();


    const username =
        document
        .getElementById('username')
        .value
        .trim();


    const password =
        document
        .getElementById('password')
        .value;


    const msg =
        document
        .getElementById('msg');


    msg.textContent =
        'جاري الاستعادة...';


    try{

        const response =
            await fetch(
                '/api/admin/recover',
                {
                    method:'POST',

                    headers:{
                        'Content-Type':
                            'application/json'
                    },

                    body:JSON.stringify({

                        code,

                        username,

                        password

                    })
                }
            );


        const data =
            await response.json();


        if(!response.ok){

            throw new Error(
                data.message
                ||
                'تعذر الاستعادة'
            );
        }


        localStorage.setItem(
            'shrh_admin_token',
            data.token
        );


        msg.textContent =
            'تمت استعادة الحساب ✅';


        setTimeout(
            () => {

                location.href =
                    '/admin.html';

            },
            800
        );


    }catch(error){

        msg.textContent =
            '❌ ' +
            error.message;

    }
}

</script>

</body>

</html>

        `);
    }
);


/* =========================================================
   ADMIN RECOVERY API
========================================================= */

app.post(
    '/api/admin/recover',
    requireDatabase,
    async (req, res) => {

        try {

            const code =
                String(
                    req.body.code || ''
                ).trim();


            const username =
                String(
                    req.body.username || ''
                ).trim();


            const password =
                String(
                    req.body.password || ''
                );


            if (
                !process.env.ADMIN_RECOVERY_CODE
                ||
                code !==
                    process.env.ADMIN_RECOVERY_CODE
            ) {

                return res.status(403).json({

                    success: false,

                    message:
                        'رمز الاستعادة غير صحيح'

                });
            }


            if (
                username.length < 3
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        'اسم المستخدم يجب أن يكون 3 أحرف على الأقل'

                });
            }


            if (
                password.length < 8
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        'كلمة المرور يجب أن تكون 8 أحرف على الأقل'

                });
            }


            const hash =
                await bcrypt.hash(
                    password,
                    12
                );


            const ownerResult =
                await pool.query(`
                    SELECT *
                    FROM admins

                    ORDER BY
                        is_owner DESC,
                        id ASC

                    LIMIT 1
                `);


            let admin;


            if (
                ownerResult.rows.length === 0
            ) {

                const result =
                    await pool.query(`
                        INSERT INTO admins
                        (
                            username,
                            password_hash,

                            can_manage_lessons,
                            can_manage_admins,
                            can_view_stats,

                            can_manage_catalog,
                            can_manage_settings,
                            can_view_activity,

                            is_owner
                        )

                        VALUES
                        (
                            $1,
                            $2,

                            TRUE,
                            TRUE,
                            TRUE,

                            TRUE,
                            TRUE,
                            TRUE,

                            TRUE
                        )

                        RETURNING *
                    `, [
                        username,
                        hash
                    ]);


                admin =
                    result.rows[0];

            } else {

                const result =
                    await pool.query(`
                        UPDATE admins

                        SET

                            username = $1,

                            password_hash = $2,

                            can_manage_lessons = TRUE,

                            can_manage_admins = TRUE,

                            can_view_stats = TRUE,

                            can_manage_catalog = TRUE,

                            can_manage_settings = TRUE,

                            can_view_activity = TRUE,

                            is_owner = TRUE

                        WHERE id = $3

                        RETURNING *
                    `, [
                        username,
                        hash,
                        ownerResult.rows[0].id
                    ]);


                admin =
                    result.rows[0];
            }


            await pool.query(`
                DELETE FROM admin_sessions

                WHERE admin_id = $1
            `, [
                admin.id
            ]);


            const token =
                await createSession(
                    admin.id
                );


            const safe =
                safeAdmin(
                    admin
                );


            await logActivity(

                safe,

                'استعادة حساب الأدمن',

                'admin',

                admin.id,

                `تمت استعادة الحساب: ${username}`

            );


            res.json({

                success: true,

                token,

                admin: safe

            });


        } catch (error) {

            console.error(
                'RECOVERY ERROR:',
                error
            );


            res.status(500).json({

                success: false,

                message:
                    'تعذر استعادة حساب الأدمن: '
                    +
                    error.message

            });
        }
    }
);


/* =========================================================
   FIRST ADMIN
========================================================= */

app.post(
    '/api/admin/setup',
    requireDatabase,
    async (req, res) => {

        try {

            const username =
                String(
                    req.body.username || ''
                ).trim();


            const password =
                String(
                    req.body.password || ''
                );


            if (
                username.length < 3
                ||
                password.length < 8
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        'اسم المستخدم 3 أحرف على الأقل وكلمة المرور 8 أحرف على الأقل'

                });
            }


            const count =
                await pool.query(`
                    SELECT
                        COUNT(*)::int AS count
                    FROM admins
                `);


            if (
                Number(
                    count.rows[0].count
                ) > 0
            ) {

                return res.status(403).json({

                    success: false,

                    message:
                        'تم إنشاء حساب الأدمن الأول مسبقًا'

                });
            }


            const hash =
                await bcrypt.hash(
                    password,
                    12
                );


            const result =
                await pool.query(`
                    INSERT INTO admins
                    (
                        username,
                        password_hash,

                        can_manage_lessons,
                        can_manage_admins,
                        can_view_stats,

                        can_manage_catalog,
                        can_manage_settings,
                        can_view_activity,

                        is_owner
                    )

                    VALUES
                    (
                        $1,
                        $2,

                        TRUE,
                        TRUE,
                        TRUE,

                        TRUE,
                        TRUE,
                        TRUE,

                        TRUE
                    )

                    RETURNING *
                `, [
                    username,
                    hash
                ]);


            const admin =
                result.rows[0];


            const token =
                await createSession(
                    admin.id
                );


            const safe =
                safeAdmin(
                    admin
                );


            await logActivity(

                safe,

                'إنشاء أول أدمن',

                'admin',

                admin.id,

                `تم إنشاء الحساب: ${username}`

            );


            res.status(201).json({

                success: true,

                token,

                admin: safe

            });


        } catch (error) {

            console.error(error);


            res.status(500).json({

                success: false,

                message:
                    'تعذر إنشاء الأدمن'

            });
        }
    }
);


/* =========================================================
   LOGIN
========================================================= */

app.post(
    '/api/admin/login',
    requireDatabase,
    async (req, res) => {

        try {

            const username =
                String(
                    req.body.username || ''
                ).trim();


            const password =
                String(
                    req.body.password || ''
                );


            if (
                !username
                ||
                !password
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        'اكتب اسم المستخدم وكلمة المرور'

                });
            }


            const result =
                await pool.query(`
                    SELECT *
                    FROM admins

                    WHERE
                        LOWER(username)
                        =
                        LOWER($1)

                    LIMIT 1
                `, [
                    username
                ]);


            const admin =
                result.rows[0];


            if (!admin) {

                return res.status(401).json({

                    success: false,

                    message:
                        'اسم المستخدم أو كلمة المرور غير صحيحة'

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
                        'اسم المستخدم أو كلمة المرور غير صحيحة'

                });
            }


            const token =
                await createSession(
                    admin.id
                );


            const safe =
                safeAdmin(
                    admin
                );


            await logActivity(

                safe,

                'تسجيل دخول',

                'admin',

                admin.id,

                'تم تسجيل الدخول'

            );


            res.json({

                success: true,

                token,

                admin: safe

            });


        } catch (error) {

            console.error(error);


            res.status(500).json({

                success: false,

                message:
                    'تعذر تسجيل الدخول'

            });
        }
    }
);


/* =========================================================
   CURRENT ADMIN
========================================================= */

app.get(
    '/api/admin/me',
    requireDatabase,
    requireAdmin,
    (req, res) => {

        res.json({

            success: true,

            admin:
                safeAdmin(
                    req.admin
                )

        });
    }
);


/* =========================================================
   LOGOUT
========================================================= */

app.post(
    '/api/admin/logout',
    requireDatabase,
    requireAdmin,
    async (req, res) => {

        try {

            const token =
                String(
                    req.headers[
                        'x-admin-token'
                    ]
                    ||
                    ''
                ).trim();


            await logActivity(

                req.admin,

                'تسجيل خروج',

                'admin',

                req.admin.id,

                'تم تسجيل الخروج'

            );


            if (token) {

                await pool.query(`
                    DELETE FROM admin_sessions

                    WHERE token = $1
                `, [
                    token
                ]);
            }


            res.json({

                success: true

            });


        } catch (error) {

            console.error(error);


            res.status(500).json({

                success: false,

                message:
                    'تعذر تسجيل الخروج'

            });
        }
    }
);


/* =========================================================
   CATALOG
========================================================= */

const typeLabels = {

    semester: 'الفصل',

    grade: 'الصف',

    subject: 'المادة'
};


async function getCatalogItems(
    type
) {

    const result =
        await pool.query(`
            SELECT
                id,
                type,
                name,
                parent_id,
                enabled,
                created_at,
                updated_at

            FROM catalog_items

            WHERE type = $1

            ORDER BY id
        `, [
            type
        ]);


    return result.rows;
}


async function catalogCreate(
    req,
    res,
    type
) {

    try {

        const name =
            String(
                req.body.name || ''
            ).trim();


        if (!name) {

            return res.status(400).json({

                success: false,

                message:
                    `اكتب اسم ${typeLabels[type]}`

            });
        }


        let parentId = null;


        if (
            type === 'subject'
            &&
            req.body.parent_id
        ) {

            parentId =
                Number(
                    req.body.parent_id
                );
        }


        if (
            type === 'subject'
            &&
            parentId
        ) {

            const parent =
                await pool.query(`
                    SELECT id
                    FROM catalog_items

                    WHERE
                        id = $1
                        AND type = 'grade'
                `, [
                    parentId
                ]);


            if (
                !parent.rows.length
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        'الصف المرتبط غير موجود'

                });
            }
        }


        const result =
            await pool.query(`
                INSERT INTO catalog_items
                (
                    type,
                    name,
                    parent_id,
                    enabled
                )

                VALUES
                (
                    $1,
                    $2,
                    $3,
                    TRUE
                )

                RETURNING *
            `, [
                type,
                name,
                parentId
            ]);


        const item =
            result.rows[0];


        await logActivity(

            req.admin,

            `إضافة ${typeLabels[type]}`,

            type,

            item.id,

            `تمت إضافة: ${name}`

        );


        res.status(201).json({

            success: true,

            item

        });


    } catch (error) {

        console.error(error);


        res.status(500).json({

            success: false,

            message:
                `تعذر إضافة ${typeLabels[type]}`

        });
    }
}


async function catalogUpdate(
    req,
    res,
    type
) {

    try {

        const id =
            Number(
                req.params.id
            );


        const name =
            String(
                req.body.name || ''
            ).trim();


        const enabled =
            req.body.enabled === undefined
                ? true
                : Boolean(
                    req.body.enabled
                );


        if (
            !Number.isInteger(id)
            ||
            !name
        ) {

            return res.status(400).json({

                success: false,

                message:
                    'البيانات غير صحيحة'

            });
        }


        const result =
            await pool.query(`
                UPDATE catalog_items

                SET

                    name = $1,

                    enabled = $2,

                    updated_at = NOW()

                WHERE
                    id = $3

                    AND type = $4

                RETURNING *
            `, [
                name,
                enabled,
                id,
                type
            ]);


        if (
            !result.rows.length
        ) {

            return res.status(404).json({

                success: false,

                message:
                    'العنصر غير موجود'

            });
        }


        await logActivity(

            req.admin,

            `تعديل ${typeLabels[type]}`,

            type,

            id,

            `تم التعديل: ${name}`

        );


        res.json({

            success: true,

            item:
                result.rows[0]

        });


    } catch (error) {

        console.error(error);


        res.status(500).json({

            success: false,

            message:
                `تعذر تعديل ${typeLabels[type]}`

        });
    }
}


async function catalogDelete(
    req,
    res,
    type
) {

    try {

        const id =
            Number(
                req.params.id
            );


        const result =
            await pool.query(`
                DELETE FROM catalog_items

                WHERE
                    id = $1

                    AND type = $2

                RETURNING *
            `, [
                id,
                type
            ]);


        if (
            !result.rows.length
        ) {

            return res.status(404).json({

                success: false,

                message:
                    'العنصر غير موجود'

            });
        }


        await logActivity(

            req.admin,

            `حذف ${typeLabels[type]}`,

            type,

            id,

            `تم الحذف: ${result.rows[0].name}`

        );


        res.json({

            success: true

        });


    } catch (error) {

        console.error(error);


        res.status(500).json({

            success: false,

            message:
                `تعذر حذف ${typeLabels[type]}`

        });
    }
}


/* =========================================================
   COMPATIBILITY ROUTES FOR CURRENT ADMIN.HTML
========================================================= */

for (
    const type
    of [
        'semester',
        'grade',
        'subject'
    ]
) {

    app.get(
        `/api/admin/${type}s`,
        requireDatabase,
        requireAdmin,
        async (req, res) => {

            try {

                res.json({

                    success: true,

                    items:
                        await getCatalogItems(
                            type
                        )

                });

            } catch (error) {

                console.error(error);


                res.status(500).json({

                    success: false,

                    message:
                        'تعذر تحميل المحتوى'

                });
            }
        }
    );


    app.post(
        `/api/admin/${type}s`,
        requireDatabase,
        requireAdmin,
        requirePermission(
            'can_manage_catalog'
        ),
        (req, res) =>
            catalogCreate(
                req,
                res,
                type
            )
    );


    app.put(
        `/api/admin/${type}s/:id`,
        requireDatabase,
        requireAdmin,
        requirePermission(
            'can_manage_catalog'
        ),
        (req, res) =>
            catalogUpdate(
                req,
                res,
                type
            )
    );


    app.delete(
        `/api/admin/${type}s/:id`,
        requireDatabase,
        requireAdmin,
        requirePermission(
            'can_manage_catalog'
        ),
        (req, res) =>
            catalogDelete(
                req,
                res,
                type
            )
    );
}


/* =========================================================
   UNIFIED CATALOG API
========================================================= */

app.get(
    '/api/admin/catalog',
    requireDatabase,
    requireAdmin,
    async (req, res) => {

        try {

            const result =
                await pool.query(`
                    SELECT *

                    FROM catalog_items

                    ORDER BY
                        type,
                        id
                `);


            res.json({

                success: true,

                items:
                    result.rows

            });


        } catch (error) {

            console.error(error);


            res.status(500).json({

                success: false,

                message:
                    'تعذر تحميل المحتوى'

            });
        }
    }
);


/* =========================================================
   LESSONS PUBLIC
========================================================= */

app.get(
    '/api/lessons',
    requireDatabase,
    async (req, res) => {

        try {

            const result =
                await pool.query(`
                    SELECT *

                    FROM lessons

                    WHERE enabled = TRUE

                    ORDER BY id DESC

                    LIMIT 500
                `);


            let items =
                result.rows;


            const semester =
                String(
                    req.query.semester
                    ||
                    ''
                ).trim();


            const grade =
                String(
                    req.query.grade
                    ||
                    ''
                ).trim();


            const subject =
                String(
                    req.query.subject
                    ||
                    ''
                ).trim();


            if (semester) {

                items =
                    items.filter(
                        x =>
                            String(
                                x.semester
                                ||
                                ''
                            )
                            ===
                            semester
                    );
            }


            if (grade) {

                items =
                    items.filter(
                        x =>
                            String(
                                x.grade
                                ||
                                ''
                            )
                            ===
                            grade
                    );
            }


            if (subject) {

                items =
                    items.filter(
                        x =>
                            String(
                                x.subject
                                ||
                                ''
                            )
                            ===
                            subject
                    );
            }


            res.json({

                success: true,

                items

            });


        } catch (error) {

            console.error(error);


            res.status(500).json({

                success: false,

                message:
                    'تعذر تحميل الدروس'

            });
        }
    }
);


/* =========================================================
   LESSONS ADMIN
========================================================= */

app.get(
    '/api/admin/lessons',
    requireDatabase,
    requireAdmin,
    async (req, res) => {

        try {

            const result =
                await pool.query(`
                    SELECT *

                    FROM lessons

                    ORDER BY id DESC
                `);


            res.json({

                success: true,

                items:
                    result.rows

            });


        } catch (error) {

            console.error(error);


            res.status(500).json({

                success: false,

                message:
                    'تعذر تحميل الدروس'

            });
        }
    }
);


app.post(
    '/api/admin/lessons',
    requireDatabase,
    requireAdmin,
    requirePermission(
        'can_manage_lessons'
    ),
    async (req, res) => {

        try {

            const semester =
                String(
                    req.body.semester
                    ||
                    ''
                ).trim();


            const grade =
                String(
                    req.body.grade
                    ||
                    ''
                ).trim();


            const subject =
                String(
                    req.body.subject
                    ||
                    ''
                ).trim();


            const title =
                String(
                    req.body.title
                    ||
                    ''
                ).trim();


            const description =
                String(
                    req.body.description
                    ||
                    ''
                );


            const summary =
                String(
                    req.body.summary
                    ||
                    ''
                );


            const videoUrl =
                String(
                    req.body.video_url
                    ||
                    ''
                ).trim();


            if (!title) {

                return res.status(400).json({

                    success: false,

                    message:
                        'اكتب عنوان الدرس'

                });
            }


            const result =
                await pool.query(`
                    INSERT INTO lessons
                    (
                        semester,
                        grade,
                        subject,
                        title,
                        description,
                        summary,
                        video_url,
                        enabled
                    )

                    VALUES
                    (
                        $1,
                        $2,
                        $3,
                        $4,
                        $5,
                        $6,
                        $7,
                        TRUE
                    )

                    RETURNING *
                `, [
                    semester,
                    grade,
                    subject,
                    title,
                    description,
                    summary,
                    videoUrl
                ]);


            await logActivity(

                req.admin,

                'إضافة درس',

                'lesson',

                result.rows[0].id,

                `تمت إضافة الدرس: ${title}`

            );


            res.status(201).json({

                success: true,

                item:
                    result.rows[0]

            });


        } catch (error) {

            console.error(error);


            res.status(500).json({

                success: false,

                message:
                    'تعذر إضافة الدرس'

            });
        }
    }
);


app.put(
    '/api/admin/lessons/:id',
    requireDatabase,
    requireAdmin,
    requirePermission(
        'can_manage_lessons'
    ),
    async (req, res) => {

        try {

            const id =
                Number(
                    req.params.id
                );


            const semester =
                String(
                    req.body.semester
                    ||
                    ''
                ).trim();


            const grade =
                String(
                    req.body.grade
                    ||
                    ''
                ).trim();


            const subject =
                String(
                    req.body.subject
                    ||
                    ''
                ).trim();


            const title =
                String(
                    req.body.title
                    ||
                    ''
                ).trim();


            const description =
                String(
                    req.body.description
                    ||
                    ''
                );


            const summary =
                String(
                    req.body.summary
                    ||
                    ''
                );


            const videoUrl =
                String(
                    req.body.video_url
                    ||
                    ''
                ).trim();


            const enabled =
                req.body.enabled === undefined

                    ? true

                    : Boolean(
                        req.body.enabled
                    );


            if (!title) {

                return res.status(400).json({

                    success: false,

                    message:
                        'اكتب عنوان الدرس'

                });
            }


            const result =
                await pool.query(`
                    UPDATE lessons

                    SET

                        semester = $1,

                        grade = $2,

                        subject = $3,

                        title = $4,

                        description = $5,

                        summary = $6,

                        video_url = $7,

                        enabled = $8,

                        updated_at = NOW()

                    WHERE
                        id = $9

                    RETURNING *
                `, [
                    semester,
                    grade,
                    subject,
                    title,
                    description,
                    summary,
                    videoUrl,
                    enabled,
                    id
                ]);


            if (
                !result.rows.length
            ) {

                return res.status(404).json({

                    success: false,

                    message:
                        'الدرس غير موجود'

                });
            }


            await logActivity(

                req.admin,

                'تعديل درس',

                'lesson',

                id,

                `تم تعديل الدرس: ${title}`

            );


            res.json({

                success: true,

                item:
                    result.rows[0]

            });


        } catch (error) {

            console.error(error);


            res.status(500).json({

                success: false,

                message:
                    'تعذر تعديل الدرس'

            });
        }
    }
);


app.delete(
    '/api/admin/lessons/:id',
    requireDatabase,
    requireAdmin,
    requirePermission(
        'can_manage_lessons'
    ),
    async (req, res) => {

        try {

            const id =
                Number(
                    req.params.id
                );


            const result =
                await pool.query(`
                    DELETE FROM lessons

                    WHERE
                        id = $1

                    RETURNING *
                `, [
                    id
                ]);


            if (
                !result.rows.length
            ) {

                return res.status(404).json({

                    success: false,

                    message:
                        'الدرس غير موجود'

                });
            }


            await logActivity(

                req.admin,

                'حذف درس',

                'lesson',

                id,

                `تم حذف الدرس: ${result.rows[0].title}`

            );


            res.json({

                success: true

            });


        } catch (error) {

            console.error(error);


            res.status(500).json({

                success: false,

                message:
                    'تعذر حذف الدرس'

            });
        }
    }
);


/* =========================================================
   QUESTIONS
========================================================= */

app.get(
    '/api/admin/questions',
    requireDatabase,
    requireAdmin,
    async (req, res) => {

        try {

            const result =
                await pool.query(`
                    SELECT *

                    FROM questions

                    ORDER BY id DESC
                `);


            res.json({

                success: true,

                items:
                    result.rows

            });


        } catch (error) {

            console.error(error);


            res.status(500).json({

                success: false,

                message:
                    'تعذر تحميل الأسئلة'

            });
        }
    }
);


app.post(
    '/api/admin/questions',
    requireDatabase,
    requireAdmin,
    requirePermission(
        'can_manage_lessons'
    ),
    async (req, res) => {

        try {

            const lessonId =
                req.body.lesson_id
                    ? Number(
                        req.body.lesson_id
                    )
                    : null;


            const question =
                String(
                    req.body.question
                    ||
                    ''
                ).trim();


            const options =
                Array.isArray(
                    req.body.options
                )
                    ? req.body.options
                    : [];


            const correctAnswer =
                Number(
                    req.body.correct_answer
                    ??
                    0
                );


            const explanation =
                String(
                    req.body.explanation
                    ||
                    ''
                );


            if (!question) {

                return res.status(400).json({

                    success: false,

                    message:
                        'اكتب السؤال'

                });
            }


            const result =
                await pool.query(`
                    INSERT INTO questions
                    (
                        lesson_id,
                        question,
                        options,
                        correct_answer,
                        explanation,
                        enabled
                    )

                    VALUES
                    (
                        $1,
                        $2,
                        $3,
                        $4,
                        $5,
                        TRUE
                    )

                    RETURNING *
                `, [
                    lessonId,
                    question,
                    JSON.stringify(
                        options
                    ),
                    correctAnswer,
                    explanation
                ]);


            await logActivity(

                req.admin,

                'إضافة سؤال',

                'question',

                result.rows[0].id,

                question

            );


            res.status(201).json({

                success: true,

                item:
                    result.rows[0]

            });


        } catch (error) {

            console.error(error);


            res.status(500).json({

                success: false,

                message:
                    'تعذر إضافة السؤال'

            });
        }
    }
);


app.get(
    '/api/questions',
    requireDatabase,
    async (req, res) => {

        try {

            const lessonId =
                Number(
                    req.query.lesson_id
                );


            if (
                !Number.isInteger(
                    lessonId
                )
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        'lesson_id غير صحيح'

                });
            }


            const result =
                await pool.query(`
                    SELECT
                        id,
                        lesson_id,
                        question,
                        options,
                        correct_answer,
                        explanation

                    FROM questions

                    WHERE

                        lesson_id = $1

                        AND enabled = TRUE

                    ORDER BY id
                `, [
                    lessonId
                ]);


            res.json({

                success: true,

                items:
                    result.rows

            });


        } catch (error) {

            console.error(error);


            res.status(500).json({

                success: false,

                message:
                    'تعذر تحميل الأسئلة'

            });
        }
    }
);


/* =========================================================
   ADMIN ACCOUNTS
========================================================= */

app.get(
    '/api/admin/accounts',
    requireDatabase,
    requireAdmin,
    requirePermission(
        'can_manage_admins'
    ),
    async (req, res) => {

        try {

            const result =
                await pool.query(`
                    SELECT *

                    FROM admins

                    ORDER BY id
                `);


            res.json({

                success: true,

                items:
                    result.rows.map(
                        safeAdminAccount
                    )

            });


        } catch (error) {

            console.error(error);


            res.status(500).json({

                success: false,

                message:
                    'تعذر تحميل حسابات الأدمن'

            });
        }
    }
);


app.post(
    '/api/admin/accounts',
    requireDatabase,
    requireAdmin,
    requirePermission(
        'can_manage_admins'
    ),
    async (req, res) => {

        try {

            const username =
                String(
                    req.body.username
                    ||
                    ''
                ).trim();


            const password =
                String(
                    req.body.password
                    ||
                    ''
                );


            const content =
                Boolean(
                    req.body.can_manage_content
                );


            const admins =
                Boolean(
                    req.body.can_manage_admins
                );


            const stats =
                Boolean(
                    req.body.can_view_stats
                );


            const settings =
                Boolean(
                    req.body.can_manage_settings
                );


            if (
                username.length < 3
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        'اسم المستخدم 3 أحرف على الأقل'

                });
            }


            if (
                password.length < 8
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        'كلمة المرور 8 أحرف على الأقل'

                });
            }


            const exists =
                await pool.query(`
                    SELECT id

                    FROM admins

                    WHERE
                        LOWER(username)
                        =
                        LOWER($1)

                    LIMIT 1
                `, [
                    username
                ]);


            if (
                exists.rows.length
            ) {

                return res.status(409).json({

                    success: false,

                    message:
                        'اسم المستخدم موجود بالفعل'

                });
            }


            const hash =
                await bcrypt.hash(
                    password,
                    12
                );


            const result =
                await pool.query(`
                    INSERT INTO admins
                    (
                        username,
                        password_hash,

                        can_manage_lessons,
                        can_manage_admins,
                        can_view_stats,

                        can_manage_catalog,
                        can_manage_settings,
                        can_view_activity,

                        is_owner
                    )

                    VALUES
                    (
                        $1,
                        $2,

                        $3,
                        $4,
                        $5,

                        $3,
                        $6,
                        $4,

                        FALSE
                    )

                    RETURNING *
                `, [
                    username,
                    hash,
                    content,
                    admins,
                    stats,
                    settings
                ]);


            const admin =
                result.rows[0];


            await logActivity(

                req.admin,

                'إضافة أدمن',

                'admin',

                admin.id,

                `تم إنشاء: ${username}`

            );


            res.status(201).json({

                success: true,

                item:
                    safeAdminAccount(
                        admin
                    )

            });


        } catch (error) {

            console.error(error);


            res.status(500).json({

                success: false,

                message:
                    'تعذر إنشاء حساب الأدمن'

            });
        }
    }
);


/* =========================================================
   UPDATE ADMIN PERMISSIONS
========================================================= */

app.put(
    '/api/admin/accounts/:id/permissions',
    requireDatabase,
    requireAdmin,
    requirePermission(
        'can_manage_admins'
    ),
    async (req, res) => {

        try {

            const id =
                Number(
                    req.params.id
                );


            const targetResult =
                await pool.query(`
                    SELECT *

                    FROM admins

                    WHERE id = $1
                `, [
                    id
                ]);


            const target =
                targetResult.rows[0];


            if (!target) {

                return res.status(404).json({

                    success: false,

                    message:
                        'الحساب غير موجود'

                });
            }


            if (
                target.is_owner
                &&
                target.id !== req.admin.id
            ) {

                return res.status(403).json({

                    success: false,

                    message:
                        'لا يمكن تعديل صلاحيات مالك الموقع'

                });
            }


            const content =
                Boolean(
                    req.body.can_manage_content
                );


            const admins =
                Boolean(
                    req.body.can_manage_admins
                );


            const stats =
                Boolean(
                    req.body.can_view_stats
                );


            const settings =
                Boolean(
                    req.body.can_manage_settings
                );


            const result =
                await pool.query(`
                    UPDATE admins

                    SET

                        can_manage_lessons = $1,

                        can_manage_catalog = $1,

                        can_manage_admins = $2,

                        can_view_stats = $3,

                        can_manage_settings = $4,

                        can_view_activity = $2

                    WHERE id = $5

                    RETURNING *
                `, [
                    content,
                    admins,
                    stats,
                    settings,
                    id
                ]);


            await logActivity(

                req.admin,

                'تعديل صلاحيات أدمن',

                'admin',

                id,

                `تم تعديل: ${target.username}`

            );


            res.json({

                success: true,

                item:
                    safeAdminAccount(
                        result.rows[0]
                    )

            });


        } catch (error) {

            console.error(error);


            res.status(500).json({

                success: false,

                message:
                    'تعذر تعديل الصلاحيات'

            });
        }
    }
);


/* =========================================================
   CHANGE ADMIN PASSWORD
========================================================= */

app.put(
    '/api/admin/accounts/:id/password',
    requireDatabase,
    requireAdmin,
    requirePermission(
        'can_manage_admins'
    ),
    async (req, res) => {

        try {

            const id =
                Number(
                    req.params.id
                );


            const newPassword =
                String(
                    req.body.new_password
                    ||
                    ''
                );


            if (
                newPassword.length < 8
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        'كلمة المرور 8 أحرف على الأقل'

                });
            }


            const targetResult =
                await pool.query(`
                    SELECT *

                    FROM admins

                    WHERE id = $1
                `, [
                    id
                ]);


            const target =
                targetResult.rows[0];


            if (!target) {

                return res.status(404).json({

                    success: false,

                    message:
                        'الحساب غير موجود'

                });
            }


            if (
                target.is_owner
                &&
                target.id !== req.admin.id
            ) {

                return res.status(403).json({

                    success: false,

                    message:
                        'لا يمكن تغيير كلمة مرور مالك الموقع'

                });
            }


            const hash =
                await bcrypt.hash(
                    newPassword,
                    12
                );


            await pool.query(`
                UPDATE admins

                SET password_hash = $1

                WHERE id = $2
            `, [
                hash,
                id
            ]);


            await pool.query(`
                DELETE FROM admin_sessions

                WHERE admin_id = $1
            `, [
                id
            ]);


            await logActivity(

                req.admin,

                'تغيير كلمة مرور أدمن',

                'admin',

                id,

                target.username

            );


            res.json({

                success: true

            });


        } catch (error) {

            console.error(error);


            res.status(500).json({

                success: false,

                message:
                    'تعذر تغيير كلمة المرور'

            });
        }
    }
);


/* =========================================================
   CHANGE MY PASSWORD
========================================================= */

app.put(
    '/api/admin/password',
    requireDatabase,
    requireAdmin,
    async (req, res) => {

        try {

            const newPassword =
                String(
                    req.body.new_password
                    ||
                    ''
                );


            if (
                newPassword.length < 8
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        'كلمة المرور 8 أحرف على الأقل'

                });
            }


            const hash =
                await bcrypt.hash(
                    newPassword,
                    12
                );


            await pool.query(`
                UPDATE admins

                SET password_hash = $1

                WHERE id = $2
            `, [
                hash,
                req.admin.id
            ]);


            await pool.query(`
                DELETE FROM admin_sessions

                WHERE admin_id = $1
            `, [
                req.admin.id
            ]);


            await logActivity(

                req.admin,

                'تغيير كلمة المرور',

                'admin',

                req.admin.id,

                req.admin.username

            );


            res.json({

                success: true

            });


        } catch (error) {

            console.error(error);


            res.status(500).json({

                success: false,

                message:
                    'تعذر تغيير كلمة المرور'

            });
        }
    }
);


/* =========================================================
   DELETE ADMIN
========================================================= */

app.delete(
    '/api/admin/accounts/:id',
    requireDatabase,
    requireAdmin,
    requirePermission(
        'can_manage_admins'
    ),
    async (req, res) => {

        try {

            const id =
                Number(
                    req.params.id
                );


            if (
                id === req.admin.id
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        'لا يمكنك حذف حسابك الحالي'

                });
            }


            const targetResult =
                await pool.query(`
                    SELECT *

                    FROM admins

                    WHERE id = $1
                `, [
                    id
                ]);


            const target =
                targetResult.rows[0];


            if (!target) {

                return res.status(404).json({

                    success: false,

                    message:
                        'الحساب غير موجود'

                });
            }


            if (target.is_owner) {

                return res.status(403).json({

                    success: false,

                    message:
                        'لا يمكن حذف مالك الموقع'

                });
            }


            await pool.query(`
                DELETE FROM admins

                WHERE id = $1
            `, [
                id
            ]);


            await logActivity(

                req.admin,

                'حذف أدمن',

                'admin',

                id,

                target.username

            );


            res.json({

                success: true

            });


        } catch (error) {

            console.error(error);


            res.status(500).json({

                success: false,

                message:
                    'تعذر حذف الحساب'

            });
        }
    }
);


/* =========================================================
   SETTINGS
========================================================= */

app.get(
    '/api/admin/settings',
    requireDatabase,
    requireAdmin,
    requirePermission(
        'can_manage_settings'
    ),
    async (req, res) => {

        try {

            const result =
                await pool.query(`
                    SELECT
                        key,
                        value

                    FROM site_settings

                    ORDER BY key
                `);


            const settings = {};


            for (
                const row
                of result.rows
            ) {

                settings[row.key] =
                    row.value;
            }


            res.json({

                success: true,

                settings

            });


        } catch (error) {

            console.error(error);


            res.status(500).json({

                success: false,

                message:
                    'تعذر تحميل الإعدادات'

            });
        }
    }
);


app.put(
    '/api/admin/settings',
    requireDatabase,
    requireAdmin,
    requirePermission(
        'can_manage_settings'
    ),
    async (req, res) => {

        try {

            const allowed = [

                'site_name',

                'site_title',

                'welcome_title',

                'welcome_text',

                'search_placeholder',

                'footer_text',

                'theme_color',

                'youtube_enabled',

                'web_enabled',

                'quiz_enabled',

                'general_info_enabled',

                'site_enabled'

            ];


            for (
                const key
                of allowed
            ) {

                if (
                    req.body[key]
                    ===
                    undefined
                ) {
                    continue;
                }


                await pool.query(`
                    INSERT INTO site_settings
                    (
                        key,
                        value
                    )

                    VALUES
                    (
                        $1,
                        $2
                    )

                    ON CONFLICT (key)

                    DO UPDATE
                    SET value =
                        EXCLUDED.value
                `, [
                    key,
                    String(
                        req.body[key]
                    )
                ]);
            }


            await logActivity(

                req.admin,

                'تعديل إعدادات الموقع',

                'settings',

                null,

                'تم تحديث الإعدادات'

            );


            res.json({

                success: true

            });


        } catch (error) {

            console.error(error);


            res.status(500).json({

                success: false,

                message:
                    'تعذر حفظ الإعدادات'

            });
        }
    }
);


/* =========================================================
   PUBLIC SETTINGS
========================================================= */

app.get(
    '/api/settings',
    requireDatabase,
    async (req, res) => {

        try {

            const result =
                await pool.query(`
                    SELECT
                        key,
                        value

                    FROM site_settings
                `);


            const settings = {};


            for (
                const row
                of result.rows
            ) {

                settings[row.key] =
                    row.value;
            }


            res.json({

                success: true,

                settings

            });


        } catch (error) {

            console.error(error);


            res.status(500).json({

                success: false,

                message:
                    'تعذر تحميل إعدادات الموقع'

            });
        }
    }
);


/* =========================================================
   ACTIVITY
========================================================= */

app.get(
    '/api/admin/activity',
    requireDatabase,
    requireAdmin,
    requirePermission(
        'can_view_activity'
    ),
    async (req, res) => {

        try {

            let limit =
                Number(
                    req.query.limit
                    ||
                    200
                );


            if (
                !Number.isFinite(
                    limit
                )
            ) {

                limit = 200;
            }


            limit =
                Math.max(
                    1,
                    Math.min(
                        500,
                        Math.floor(
                            limit
                        )
                    )
                );


            const result =
                await pool.query(`
                    SELECT

                        l.id,

                        l.action,

                        l.entity_type,

                        l.entity_id,

                        l.details,

                        l.created_at,

                        a.username
                            AS admin_username

                    FROM activity_logs l

                    LEFT JOIN admins a

                        ON a.id =
                           l.admin_id

                    ORDER BY
                        l.id DESC

                    LIMIT $1
                `, [
                    limit
                ]);


            res.json({

                success: true,

                items:
                    result.rows

            });


        } catch (error) {

            console.error(error);


            res.status(500).json({

                success: false,

                message:
                    'تعذر تحميل سجل النشاط'

            });
        }
    }
);


/* =========================================================
   STATS
========================================================= */

app.get(
    '/api/admin/stats',
    requireDatabase,
    requireAdmin,
    requirePermission(
        'can_view_stats'
    ),
    async (req, res) => {

        try {

            const results =
                await Promise.all([

                    pool.query(`
                        SELECT
                            visits,
                            searches

                        FROM app_stats

                        WHERE id = 1
                    `),

                    pool.query(`
                        SELECT
                            COUNT(*)::int
                            AS count

                        FROM lessons
                    `),

                    pool.query(`
                        SELECT
                            COUNT(*)::int
                            AS count

                        FROM admins
                    `),

                    pool.query(`
                        SELECT
                            COUNT(*)::int
                            AS count

                        FROM activity_logs
                    `),

                    pool.query(`
                        SELECT
                            COUNT(*)::int
                            AS count

                        FROM catalog_items

                        WHERE
                            type = 'grade'
                    `),

                    pool.query(`
                        SELECT
                            COUNT(*)::int
                            AS count

                        FROM catalog_items

                        WHERE
                            type = 'subject'
                    `)

                ]);


            const appStats =
                results[0]
                    .rows[0]
                ||
                {
                    visits: 0,
                    searches: 0
                };


            res.json({

                success: true,

                stats: {

                    visitors:
                        Number(
                            appStats.visits
                        ),

                    users:
                        Number(
                            appStats.visits
                        ),

                    searches:
                        Number(
                            appStats.searches
                        ),

                    lessons:
                        Number(
                            results[1]
                                .rows[0]
                                .count
                        ),

                    admins:
                        Number(
                            results[2]
                                .rows[0]
                                .count
                        ),

                    activity:
                        Number(
                            results[3]
                                .rows[0]
                                .count
                        ),

                    grades:
                        Number(
                            results[4]
                                .rows[0]
                                .count
                        ),

                    subjects:
                        Number(
                            results[5]
                                .rows[0]
                                .count
                        )
                }
            });


        } catch (error) {

            console.error(error);


            res.status(500).json({

                success: false,

                message:
                    'تعذر تحميل الإحصائيات'

            });
        }
    }
);


/* =========================================================
   PUBLIC STATS
========================================================= */

app.post(
    '/api/stats/visit',
    requireDatabase,
    async (req, res) => {

        try {

            await pool.query(`
                UPDATE app_stats

                SET

                    visits =
                        visits + 1,

                    updated_at =
                        NOW()

                WHERE id = 1
            `);


            res.json({

                success: true

            });


        } catch (error) {

            res.status(500).json({

                success: false

            });
        }
    }
);


app.post(
    '/api/stats/search',
    requireDatabase,
    async (req, res) => {

        try {

            await pool.query(`
                UPDATE app_stats

                SET

                    searches =
                        searches + 1,

                    updated_at =
                        NOW()

                WHERE id = 1
            `);


            res.json({

                success: true

            });


        } catch (error) {

            res.status(500).json({

                success: false

            });
        }
    }
);


/* =========================================================
   YOUTUBE SEARCH
========================================================= */

app.get(
    '/api/youtube-search',
    async (req, res) => {

        try {

            const apiKey =
                process.env.YOUTUBE_API_KEY;


            if (!apiKey) {

                return res.status(503).json({

                    success: false,

                    message:
                        'YouTube API غير مفعّل'

                });
            }


            const query =
                String(
                    req.query.q
                    ||
                    ''
                ).trim();


            if (!query) {

                return res.status(400).json({

                    success: false,

                    message:
                        'اكتب عبارة البحث'

                });
            }


            const response =
                await axios.get(

                    'https://www.googleapis.com/youtube/v3/search',

                    {

                        params: {

                            part:
                                'snippet',

                            type:
                                'video',

                            maxResults:
                                8,

                            q:
                                query,

                            key:
                                apiKey
                        },

                        timeout:
                            15000
                    }
                );


            const items =
                (
                    response.data.items
                    ||
                    []
                )
                .map(
                    item => ({

                        videoId:
                            item.id?.videoId
                            ||
                            '',

                        title:
                            item.snippet?.title
                            ||
                            '',

                        channel:
                            item.snippet?.channelTitle
                            ||
                            '',

                        description:
                            item.snippet?.description
                            ||
                            '',

                        thumbnail:
                            item.snippet
                                ?.thumbnails
                                ?.high
                                ?.url

                            ||

                            item.snippet
                                ?.thumbnails
                                ?.medium
                                ?.url

                            ||

                            ''
                    })
                )
                .filter(
                    item =>
                        item.videoId
                );


            res.json({

                success: true,

                items

            });


        } catch (error) {

            console.error(
                'YouTube error:',
                error.response?.data
                ||
                error.message
            );


            res.status(500).json({

                success: false,

                message:
                    'تعذر البحث في YouTube'

            });
        }
    }
);


/* =========================================================
   API 404
========================================================= */

app.use(
    '/api',
    (req, res) => {

        res.status(404).json({

            success: false,

            message:
                'مسار API غير موجود'

        });
    }
);


/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
    (
        error,
        req,
        res,
        next
    ) => {

        console.error(
            'Server error:',
            error
        );


        if (
            res.headersSent
        ) {

            return next(
                error
            );
        }


        res.status(500).json({

            success: false,

            message:
                'حدث خطأ في الخادم'

        });
    }
);


/* =========================================================
   START
========================================================= */

async function startServer() {

    try {

        if (pool) {

            await initDatabase();

            await cleanupSessions();

        }


        app.listen(

            PORT,

            '0.0.0.0',

            () => {

                console.log(
                    `شرح دروسي يعمل على المنفذ ${PORT}`
                );

                console.log(
                    `Local: http://localhost:${PORT}`
                );

                console.log(
                    `PostgreSQL: ${
                        pool
                            ? 'Connected'
                            : 'Not configured locally'
                    }`
                );
            }
        );


    } catch (error) {

        console.error(
            'Startup error:',
            error
        );

        process.exit(1);
    }
}


startServer();
