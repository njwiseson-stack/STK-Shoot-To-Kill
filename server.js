
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const helmet = require("helmet");
const { rateLimit } = require("express-rate-limit");
const crypto = require("node:crypto");
const path = require("node:path");

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const isProduction = process.env.NODE_ENV === "production";

const requiredSettings = [
  "SESSION_SECRET",
  "DISCORD_CLIENT_ID",
  "DISCORD_CLIENT_SECRET",
  "DISCORD_REDIRECT_URI",
  "DISCORD_GUILD_ID",
  "DISCORD_BOT_TOKEN",
  "DISCORD_RECRUIT_ROLE_ID",
  "DISCORD_MEMBER_ROLE_ID",
];

const missingSettings = requiredSettings.filter(
  (key) => !process.env[key]
);

if (missingSettings.length) {
  console.error("Missing .env settings:", missingSettings.join(", "));
  process.exit(1);
}

if (
  process.env.SESSION_SECRET.length < 32 ||
  process.env.SESSION_SECRET ===
    "REPLACE_WITH_A_LONG_RANDOM_SECRET"
) {
  console.error("SESSION_SECRET must be a random secret of at least 32 characters.");
  process.exit(1);
}

if (isProduction) {
  app.set("trust proxy", 1);
}

app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({ limit: "20kb" }));
app.use(express.urlencoded({ extended: false, limit: "20kb" }));

// --------------------------------------------------
// SERVER-SIDE SESSIONS
// --------------------------------------------------

app.use(
  session({
    name: "stk.sid",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: new SQLiteStore({
      db: "sessions.db",
dir: DATA_DIR,
    }),
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: isProduction,
      maxAge: 1000 * 60 * 60 * 8,
    },
  })
);

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: "draft-7",
  legacyHeaders: false,
});

app.use("/api", limiter);

// --------------------------------------------------
// APPLICATION DATABASE
// --------------------------------------------------

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new Database(path.join(DATA_DIR, "stk.db"));

db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    discord_id TEXT NOT NULL,
    username TEXT NOT NULL,
    platform TEXT NOT NULL,
    timezone TEXT NOT NULL DEFAULT '',
    age TEXT NOT NULL,
    experience TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    reviewer_id TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS applications_status_idx
  ON applications(status);

  CREATE INDEX IF NOT EXISTS applications_discord_idx
  ON applications(discord_id);
`);

// Add the timezone column to an older database if necessary.
const applicationColumns = db
  .prepare("PRAGMA table_info(applications)")
  .all();

if (!applicationColumns.some((column) => column.name === "timezone")) {
  db.exec(`
    ALTER TABLE applications
    ADD COLUMN timezone TEXT NOT NULL DEFAULT ''
  `);
}

// --------------------------------------------------
// DISCORD ROLES
// --------------------------------------------------

const platformRoles = {
  PlayStation: process.env.DISCORD_PLATFORM_PLAYSTATION_ROLE_ID,
  Xbox: process.env.DISCORD_PLATFORM_XBOX_ROLE_ID,
  PC: process.env.DISCORD_PLATFORM_PC_ROLE_ID,
  Switch: process.env.DISCORD_PLATFORM_SWITCH_ROLE_ID,
  Mobile: process.env.DISCORD_PLATFORM_MOBILE_ROLE_ID,
};

const timezoneRoles = {
  CST: process.env.DISCORD_TIMEZONE_CST_ROLE_ID,
  PST: process.env.DISCORD_TIMEZONE_PST_ROLE_ID,
  MST: process.env.DISCORD_TIMEZONE_MST_ROLE_ID,
  EST: process.env.DISCORD_TIMEZONE_EST_ROLE_ID,
  BST: process.env.DISCORD_TIMEZONE_BST_ROLE_ID,
};

const staffIds = new Set(
  (process.env.STAFF_DISCORD_IDS || "520369689151537167")
    .split(",")
    .map((id) => id.trim())
    .filter(Boolean)
);
console.log("STK staff IDs loaded:", [...staffIds]);
console.log("Expected staff ID present:", staffIds.has("520369689151537167"));
// --------------------------------------------------
// AUTHORIZATION AND CSRF
// --------------------------------------------------

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({
      error: "Sign in with Discord first.",
    });
  }

  next();
}

function requireStaff(req, res, next) {
  if (!req.session.user || !staffIds.has(req.session.user.id)) {
    return res.status(403).json({
      error: "Staff access required.",
    });
  }

  next();
}

function requireCsrf(req, res, next) {
  const supplied = req.get("X-STK-CSRF");
  const expected = req.session.csrfToken;

  if (
    typeof supplied !== "string" ||
    typeof expected !== "string" ||
    supplied.length !== expected.length ||
    !crypto.timingSafeEqual(
      Buffer.from(supplied),
      Buffer.from(expected)
    )
  ) {
    return res.status(403).json({
      error: "Invalid security token. Refresh the page and try again.",
    });
  }

  next();
}

// --------------------------------------------------
// DISCORD API AND ROLE HELPERS
// --------------------------------------------------

async function discordRequest(endpoint, options = {}) {
  const response = await fetch(
    `https://discord.com/api/v10${endpoint}`,
    {
      ...options,
      headers: {
        Authorization: `Bot ${process.env.DISCORD_BOT_TOKEN}`,
        ...options.headers,
      },
    }
  );

  if (!response.ok) {
    const detail = await response.text();

    console.error(
      "Discord API error:",
      response.status,
      detail.slice(0, 300)
    );

    throw new Error(`Discord API request failed (${response.status}).`);
  }

  if (response.status === 204) {
    return null;
  }

  return response.json();
}

async function setRole(userId, roleId, add = true) {
  if (!roleId) {
    throw new Error("A required Discord role ID is missing.");
  }

  const method = add ? "PUT" : "DELETE";

  await discordRequest(
    `/guilds/${process.env.DISCORD_GUILD_ID}` +
      `/members/${encodeURIComponent(userId)}` +
      `/roles/${encodeURIComponent(roleId)}`,
    { method }
  );
}

async function trySetRole(userId, roleId, add = true) {
  if (!roleId) {
    console.error("A configured Discord role ID is missing.");
    return false;
  }

  try {
    await setRole(userId, roleId, add);
    return true;
  } catch (error) {
    console.error("Role assignment failed:", error.message);
    return false;
  }
}

// --------------------------------------------------
// DISCORD LOGIN
// --------------------------------------------------

app.get(
  "/auth/discord",
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 20,
    standardHeaders: "draft-7",
    legacyHeaders: false,
  }),
  (req, res) => {
    const state = crypto.randomBytes(32).toString("hex");
    req.session.oauthState = state;

    const url = new URL("https://discord.com/oauth2/authorize");

    url.searchParams.set("client_id", process.env.DISCORD_CLIENT_ID);
    url.searchParams.set("redirect_uri", process.env.DISCORD_REDIRECT_URI);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", "identify");
    url.searchParams.set("state", state);

    req.session.save((error) => {
      if (error) {
        console.error("OAuth session error:", error.message);
        return res.status(500).send("Could not start Discord login.");
      }

      res.redirect(url.toString());
    });
  }
);

app.get("/auth/discord/callback", async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    return res.status(400).send("Discord login was cancelled.");
  }

  if (
    typeof code !== "string" ||
    typeof state !== "string" ||
    typeof req.session.oauthState !== "string" ||
    state.length !== req.session.oauthState.length ||
    !crypto.timingSafeEqual(
      Buffer.from(state),
      Buffer.from(req.session.oauthState)
    )
  ) {
    return res.status(400).send("Invalid login state. Please try again.");
  }

  delete req.session.oauthState;

  try {
    const tokenResponse = await fetch(
      "https://discord.com/api/v10/oauth2/token",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          client_id: process.env.DISCORD_CLIENT_ID,
          client_secret: process.env.DISCORD_CLIENT_SECRET,
          grant_type: "authorization_code",
          code,
          redirect_uri: process.env.DISCORD_REDIRECT_URI,
        }),
      }
    );

    if (!tokenResponse.ok) {
      throw new Error("Discord token exchange failed.");
    }

    const tokens = await tokenResponse.json();

    const userResponse = await fetch(
      "https://discord.com/api/v10/users/@me",
      {
        headers: {
          Authorization: `Bearer ${tokens.access_token}`,
        },
      }
    );

    if (!userResponse.ok) {
      throw new Error("Could not retrieve your Discord account.");
    }

    const discordUser = await userResponse.json();

    await new Promise((resolve, reject) => {
      req.session.regenerate((err) => {
        if (err) reject(err);
        else resolve();
      });
    });

    req.session.user = {
      id: discordUser.id,
      username: discordUser.username,
    };

    req.session.csrfToken = crypto.randomBytes(32).toString("hex");

    await new Promise((resolve, reject) => {
      req.session.save((err) => {
        if (err) reject(err);
        else resolve();
      });
    });

    res.redirect("/");
  } catch (err) {
    console.error("Discord login failed:", err.message);

    res.status(500).send(
      "Discord login failed. Check the server terminal for details."
    );
  }
});

// --------------------------------------------------
// FRONTEND CONFIGURATION
// --------------------------------------------------

app.get("/api/config", (req, res) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");
  }

  res.set("Cache-Control", "no-store");

  res.json({
    csrfToken: req.session.csrfToken,
    user: req.session.user || null,
    isStaff: Boolean(
      req.session.user && staffIds.has(req.session.user.id)
    ),
  });
});

// --------------------------------------------------
// SUBMIT AN APPLICATION
// --------------------------------------------------

app.post(
  "/api/applications",
  requireLogin,
  requireCsrf,
  async (req, res) => {
    try {
      const platform = String(req.body.platform || "").trim();
      const timezone = String(req.body.timezone || "").trim();
      const age = String(req.body.age || "").trim();
      const experience = String(req.body.experience || "").trim();
      const reason = String(req.body.reason || "").trim();

      if (!Object.hasOwn(platformRoles, platform)) {
        return res.status(400).json({
          error: "Choose a valid gaming platform.",
        });
      }

      if (!Object.hasOwn(timezoneRoles, timezone)) {
        return res.status(400).json({
          error: "Choose a valid timezone.",
        });
      }

      if (!/^\d{1,3}$/.test(age) || Number(age) < 13 || Number(age) > 100) {
        return res.status(400).json({
          error: "Enter a valid age.",
        });
      }

      if (experience.length < 10 || experience.length > 2000) {
        return res.status(400).json({
          error: "Experience must be 10–2000 characters.",
        });
      }

      if (reason.length < 10 || reason.length > 3000) {
        return res.status(400).json({
          error: "Your reason must be 10–3000 characters.",
        });
      }

      const existing = db.prepare(`
        SELECT id, status
        FROM applications
        WHERE discord_id = ?
        ORDER BY id DESC
        LIMIT 1
      `).get(req.session.user.id);

      if (existing && existing.status !== "rejected") {
        return res.status(409).json({
          error: `You already have an application with status: ${existing.status}.`,
        });
      }

      const result = db.prepare(`
        INSERT INTO applications
          (discord_id, username, platform, timezone, age, experience, reason)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(
        req.session.user.id,
        req.session.user.username,
        platform,
        timezone,
        age,
        experience,
        reason
      );

      const recruitOK = await trySetRole(
        req.session.user.id,
        process.env.DISCORD_RECRUIT_ROLE_ID
      );

      const platformOK = await trySetRole(
        req.session.user.id,
        platformRoles[platform]
      );

      const timezoneOK = await trySetRole(
        req.session.user.id,
        timezoneRoles[timezone]
      );

      const rolesOK = recruitOK && platformOK && timezoneOK;

      res.status(201).json({
        message: rolesOK
          ? "Application submitted! Your application is awaiting staff approval."
          : "Application saved, but a Discord role could not be assigned. Please contact staff.",
        id: Number(result.lastInsertRowid),
      });
    } catch (error) {
      console.error("Application submission failed:", error.message);

      res.status(500).json({
        error: "Could not submit your application. Please try again.",
      });
    }
  }
);

// --------------------------------------------------
// VIEW YOUR OWN APPLICATION
// --------------------------------------------------

app.get("/api/my-application", requireLogin, (req, res) => {
  const application = db.prepare(`
    SELECT id, username, platform, timezone, status, created_at
    FROM applications
    WHERE discord_id = ?
    ORDER BY id DESC
    LIMIT 1
  `).get(req.session.user.id);

  res.json({ application: application || null });
});

// --------------------------------------------------
// STAFF APPLICATION LIST
// --------------------------------------------------

app.get(
  "/api/staff/applications",
  requireLogin,
  requireStaff,
  (req, res) => {
    const applications = db.prepare(`
      SELECT
        id, discord_id, username, platform, timezone,
        age, experience, reason, status, created_at
      FROM applications
      ORDER BY
        CASE WHEN status = 'pending' THEN 0 ELSE 1 END,
        id DESC
      LIMIT 200
    `).all();

    res.json({ applications });
  }
);

// --------------------------------------------------
// STAFF APPROVAL AND REJECTION
// --------------------------------------------------

app.post(
  "/api/staff/applications/:id/review",
  requireLogin,
  requireStaff,
  requireCsrf,
  async (req, res) => {
    const id = Number(req.params.id);
    const decision = req.body.decision;

    if (!Number.isSafeInteger(id) || id < 1) {
      return res.status(400).json({
        error: "Invalid application ID.",
      });
    }

    if (!["approve", "reject"].includes(decision)) {
      return res.status(400).json({
        error: "Choose approve or reject.",
      });
    }

    const application = db.prepare(`
      SELECT * FROM applications WHERE id = ?
    `).get(id);

    if (!application) {
      return res.status(404).json({
        error: "Application not found.",
      });
    }

    if (application.status !== "pending") {
      return res.status(409).json({
        error: "This application has already been reviewed.",
      });
    }

    try {
      if (decision === "approve") {
        await setRole(
          application.discord_id,
          process.env.DISCORD_MEMBER_ROLE_ID,
          true
        );

        await setRole(
          application.discord_id,
          process.env.DISCORD_RECRUIT_ROLE_ID,
          false
        );
      } else {
        await setRole(
          application.discord_id,
          process.env.DISCORD_RECRUIT_ROLE_ID,
          false
        );

        const platformRole = platformRoles[application.platform];
        const timezoneRole = timezoneRoles[application.timezone];

        if (platformRole) {
          await setRole(application.discord_id, platformRole, false);
        }

        if (timezoneRole) {
          await setRole(application.discord_id, timezoneRole, false);
        }
      }

      const updated = db.prepare(`
        UPDATE applications
        SET status = ?, reviewer_id = ?
        WHERE id = ? AND status = 'pending'
      `).run(
        decision === "approve" ? "approved" : "rejected",
        req.session.user.id,
        id
      );

      if (updated.changes !== 1) {
        return res.status(409).json({
          error: "This application was already reviewed.",
        });
      }

      res.json({
        message: `Application ${decision}d successfully.`,
        status: decision === "approve" ? "approved" : "rejected",
      });
    } catch (error) {
      console.error("Staff review failed:", error.message);

      res.status(502).json({
        error: "Discord role update failed. Check bot permissions and confirm the applicant is in the server. The application remains pending.",
      });
    }
  }
);

// --------------------------------------------------
// LOG OUT
// --------------------------------------------------

app.post("/auth/logout", requireLogin, requireCsrf, (req, res) => {
  req.session.destroy((error) => {
    if (error) {
      console.error("Logout failed:", error.message);

      return res.status(500).json({
        error: "Logout failed.",
      });
    }

    res.clearCookie("stk.sid", {
      httpOnly: true,
      sameSite: "lax",
      secure: isProduction,
    });

    res.json({ message: "Signed out." });
  });
});

// --------------------------------------------------
// SERVE THE WEBSITE
// --------------------------------------------------

app.use(express.static(path.join(__dirname, "public")));

app.use((req, res) => {
  res.status(404).send("Page not found.");
});

// --------------------------------------------------
// START
// --------------------------------------------------

app.listen(PORT, () => {
  console.log(`STK website running at http://localhost:${PORT}`);
});