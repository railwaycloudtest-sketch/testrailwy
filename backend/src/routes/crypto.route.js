import express from "express";
import {
  getCryptoConfig,
  getJwks,
  getCertFingerprint,
  getMyKeys,
  publishMyKeys,
  verifySignedToken,
} from "../controllers/crypto.controller.js";
import { protectRoute } from "../middleware/auth.middleware.js";

const router = express.Router();

router.get("/config", getCryptoConfig);
router.get("/jwks", getJwks);
router.get("/cert-fp", getCertFingerprint);

router.get("/my-keys", protectRoute, getMyKeys);
router.post("/my-keys", protectRoute, publishMyKeys);
router.post("/verify-jwt", verifySignedToken);

export default router;
