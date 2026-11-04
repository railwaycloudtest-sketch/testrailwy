/**
 * GET /uploads/:name — on-the-fly decryption of AES-256-GCM encrypted uploads.
 * Authenticated: images are only served to logged-in users (authorization).
 * Path traversal is impossible: the filename must match a strict pattern.
 */

import express from "express";
import { loadEncryptedUpload } from "../lib/upload.js";
import { protectRoute } from "../middleware/auth.middleware.js";

const router = express.Router();

router.get("/:name", protectRoute, (req, res) => {
  try {
    const file = loadEncryptedUpload(String(req.params.name));
    if (!file) return res.status(404).json({ message: "Not found" });

    res.setHeader("Content-Type", file.meta.mime);
    res.setHeader("Cache-Control", "private, max-age=86400");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.send(file.data);
  } catch (error) {
    console.error("Error serving encrypted upload:", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

export default router;
