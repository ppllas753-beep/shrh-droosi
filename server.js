require("dotenv").config();

const express = require("express");
const axios = require("axios");

const app = express();

// Render يعطي التطبيق المنفذ من خلال process.env.PORT
// وإذا كنت تشغله على جهازك محليًا سيستخدم 3000
const PORT = process.env.PORT || 3000;


/* =========================================
   Middleware
========================================= */

app.use(
    express.json()
);

app.use(
    express.static(__dirname)
);


/* =========================================
   الصفحة الرئيسية
========================================= */

app.get("/", (req, res) => {

    res.sendFile(
        __dirname + "/index.html"
    );

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
   اختبار السيرفر
========================================= */

app.get("/api/test", (req, res) => {

    res.json({

        success: true,

        message:
            "السيرفر يعمل بنجاح 🚀",

        port: PORT

    });

});


/* =========================================
   استقبال البحث
========================================= */

app.get("/api/search", (req, res) => {

    const query =
        String(
            req.query.q || ""
        ).trim();


    if (!query) {

        return res.status(400).json({

            success: false,

            message:
                "اكتب اسم الدرس"

        });

    }


    res.json({

        success: true,

        query: query,

        message:
            `تم استقبال البحث عن: ${query}`

    });

});


/* =========================================
   البحث في YouTube
========================================= */

app.get(
    "/api/youtube-search",
    async (req, res) => {

        const query =
            String(
                req.query.q || ""
            ).trim();


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

            console.error(
                "YOUTUBE_API_KEY غير موجود"
            );

            return res.status(500).json({

                success: false,

                message:
                    "مفتاح YouTube API غير موجود في إعدادات السيرفر"

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


            const items =
                Array.isArray(
                    response.data.items
                )
                    ? response.data.items
                    : [];


            res.json({

                success: true,

                items: items

            });

        } catch (error) {

            console.error(
                "YouTube API error:"
            );


            console.error(
                error.response?.data ||
                error.message
            );


            const apiError =
                error.response?.data?.error;


            let message =
                "تعذر البحث في YouTube";


            if (apiError?.message) {

                message =
                    apiError.message;

            }


            res.status(500).json({

                success: false,

                message: message

            });

        }

    }
);


/* =========================================
   معالجة الأخطاء العامة
========================================= */

app.use(
    (err, req, res, next) => {

        console.error(
            "Server error:",
            err
        );


        res.status(500).json({

            success: false,

            message:
                "حدث خطأ في السيرفر"

        });

    }
);


/* =========================================
   تشغيل السيرفر
========================================= */

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

    }
);