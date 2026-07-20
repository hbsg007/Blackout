import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { authRouter } from "./routes/auth.js";
import { scanRouter } from "./routes/scans.js";
import { scheduleRouter } from "./routes/schedules.js";

const app = express();
app.use(helmet());                       // secure default headers
app.use(cors({ origin: process.env.WEB_ORIGIN || "http://localhost:3000" }));
app.use(express.json({ limit: "1mb" }));

// Rate limit auth endpoints hard — brute-force defense.
app.use("/api/auth", rateLimit({ windowMs: 15 * 60_000, max: 30 }));

app.get("/health", (_req, res) => res.json({ status: "ok" }));
app.use("/api/auth", authRouter);
app.use("/api/scans", scanRouter);
app.use("/api/schedules", scheduleRouter);

const port = Number(process.env.PORT || 4000);
app.listen(port, () => console.log(`api listening on :${port}`));
