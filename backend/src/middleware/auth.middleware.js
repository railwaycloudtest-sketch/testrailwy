import jwt from "jsonwebtoken";
import User from "../models/User.js";
import { loadJwtKeyPair } from "../lib/crypto/keys.js";
import { toSafeUser } from "../controllers/auth.controller.js";

export const protectRoute = async (req, res, next) => {
  try {
    const token = req.cookies.jwt;

    if (!token) {
      return res.status(401).json({ message: "Unauthorized - No token provided" });
    }

    // RS256 (asymmetric): signature verified with the public key only.
    const { publicPem } = loadJwtKeyPair();
    const decoded = jwt.verify(token, publicPem, { algorithms: ["RS256"] });

    if (!decoded?.userId) {
      return res.status(401).json({ message: "Unauthorized - Invalid token" });
    }

    const user = await User.findById(decoded.userId).select("+password");
    if (!user) {
      return res.status(401).json({ message: "Unauthorized - User not found" });
    }
    // attach decrypted-at-rest stats but strip secrets downstream
    req.user = user;
    req.safeUser = toSafeUser(user);

    next();
  } catch (error) {
    if (error?.name === "TokenExpiredError") {
      return res.status(401).json({ message: "Unauthorized - Session expired" });
    }
    console.log("Error in protectRoute middleware", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
};
