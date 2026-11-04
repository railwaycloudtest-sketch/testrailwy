import express from "express";
import { login, logout, onboard, signup, updateProfile } from "../controllers/auth.controller.js";
import { protectRoute } from "../middleware/auth.middleware.js";
import { upload, saveEncryptedUpload } from "../lib/upload.js";

const router = express.Router();

router.post("/signup", signup);
router.post("/login", login);
router.post("/logout", protectRoute, logout);

router.post("/onboarding", protectRoute, onboard);

// check if user is logged in
router.get("/me", protectRoute, (req, res) => {
  res.status(200).json({ success: true, user: req.safeUser });
});

router.put("/profile", protectRoute, updateProfile);

router.post("/upload-profile-pic", protectRoute, (req, res) => {
  upload.single("profilePic")(req, res, (err) => {
    if (err) {
      if (err.code === "LIMIT_FILE_SIZE") {
        return res.status(400).json({ message: "File too large. Max 5MB" });
      }
      return res.status(400).json({ message: err.message || "Upload failed" });
    }
    try {
      if (!req.file) {
        return res.status(400).json({ message: "No file uploaded" });
      }
      const protocol = req.protocol;
      const host = req.get("host");
      // file stored AES-256-GCM encrypted at rest; served decrypted-on-the-fly
      const url = `${protocol}://${host}/uploads/${saveEncryptedUpload(req.file)}`;
      res.status(200).json({ success: true, url });
    } catch (error) {
      console.error("Error uploading profile pic:", error);
      res.status(500).json({ message: "Internal Server Error" });
    }
  });
});

export default router;
