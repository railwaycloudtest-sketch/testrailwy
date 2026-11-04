import { upsertStreamUser } from "../lib/stream.js";
import { generateAvatar } from "../lib/avatars.js";
import User from "../models/User.js";
import jwt from "jsonwebtoken";
import { sealField, openField, emailLookupHash } from "../lib/crypto/dbcrypto.js";
import { audit } from "../lib/audit.js";
import { loadJwtKeyPair } from "../lib/crypto/keys.js";

/* -------------------------------------------------------------------------- */
/* Cookie / token helpers                                                      */
/* -------------------------------------------------------------------------- */

export function isTlsEnabled() {
  return process.env.TLS_ENABLED !== "off" && process.env.NODE_ENV === "production";
}

export function authCookieSettings() {
  const secure = process.env.NODE_ENV === "production" || isTlsEnabled();
  return {
    maxAge: 7 * 24 * 60 * 60 * 1000,
    httpOnly: true, // JS cannot read it — mitigates XSS exfiltration
    sameSite: "strict", // CSRF hardening
    secure, // cookie only over https when secure
    path: "/",
  };
}

function signSessionToken(userId) {
  const { privatePem, kid } = loadJwtKeyPair();
  // RS256: asymmetric JWT signed with RSA-3072 (P-256?). kid enables rotation.
  return jwt.sign({ userId }, privatePem, {
    algorithm: "RS256",
    keyid: kid,
    expiresIn: "7d",
  });
}

/** Serialize a user for API responses — decrypts at-rest fields, strips secrets. */
export function toSafeUser(user) {
  const doc = user;
  const obj = {
    _id: doc._id?.toString?.() ?? doc._id,
    fullName: doc.fullName,
    email: doc.emailEnc ? openField("email", doc.emailEnc) : (doc.email || ""),
    bio: doc.bioEnc ? openField("bio", doc.bioEnc) : (doc.bio || ""),
    location: doc.locationEnc ? openField("location", doc.locationEnc) : (doc.location || ""),
    profilePic: doc.profilePic,
    nativeLanguage: doc.nativeLanguage,
    learningLanguage: doc.learningLanguage,
    isOnboarded: doc.isOnboarded,
    isOnline: doc.isOnline,
    lastSeen: doc.lastSeen,
    notificationsViewedAt: doc.notificationsViewedAt,
    friends: doc.friends,
    publicKeys: doc.publicKeys ?? undefined,
    createdAt: doc.createdAt,
    updatedAt: doc.updatedAt,
  };
  // delete undefined entries so documents stay slim
  for (const k of Object.keys(obj)) if (obj[k] === undefined) delete obj[k];
  return obj;
}

/* -------------------------------------------------------------------------- */
/* Controllers                                                                 */
/* -------------------------------------------------------------------------- */

export async function signup(req, res) {
  const { email, password, fullName } = req.body;

  try {
    if (!email || !password || !fullName) {
      return res.status(400).json({ message: "All fields are required" });
    }

    if (password.length < 6) {
      return res.status(400).json({ message: "Password must be at least 6 characters" });
    }

    // password strength guard — force mixed content for weak-6 passwords
    if (!/[a-zA-Z]/.test(password) || !/[0-9]/.test(password)) {
      return res.status(400).json({
        message: "Password must contain at least one letter and one number",
      });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email) || email.length > 254) {
      return res.status(400).json({ message: "Invalid email format" });
    }

    const emailNorm = String(email).trim().toLowerCase();
    const existingUser = await User.findOne({ emailHmac: emailLookupHash(emailNorm) });
    if (existingUser) {
      await audit("signup.duplicate", { meta: { emailHashed: false } });
      return res.status(400).json({ message: "Email already exists, please use a diffrent one" });
    }

    const idx = Math.floor(Math.random() * 100) + 1;
    const randomAvatar = generateAvatar(fullName, idx);

    const newUser = await User.create({
      fullName,
      password,
      emailHmac: emailLookupHash(emailNorm),
      emailEnc: sealField("email", emailNorm),
      bioEnc: "",
      locationEnc: "",
      profilePic: randomAvatar,
    });

    try {
      await upsertStreamUser({
        id: newUser._id.toString(),
        name: newUser.fullName,
        image: newUser.profilePic || "",
      });
      console.log(`Stream user created for ${newUser.fullName}`);
    } catch (error) {
      console.log("Error creating Stream user:", error);
    }

    // immediately authenticate the new user (session cookie)
    const token = signSessionToken(newUser._id);
    res.cookie("jwt", token, authCookieSettings());

    try {
      await audit("signup", { actor: newUser._id.toString(), meta: {} });
    } catch { /* non-fatal */ }

    const safeUser = toSafeUser(newUser);
    return res.status(201).json({ success: true, user: safeUser });
  } catch (error) {
    console.log("Error in signup controller", error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
}

export async function login(req, res) {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const emailNorm = String(email).trim().toLowerCase();
    const hmac = emailLookupHash(emailNorm);
    const user = await User.findOne({
      $or: [{ emailHmac: hmac }, { email: emailNorm }],
    }).select("+password");
    if (!user) {
      // uniform error for unknown email OR wrong password (no user enumeration)
      await audit("login.failed", { meta: { reason: "unknown-email" } });
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const isPasswordCorrect = await user.matchPassword(password);
    if (!isPasswordCorrect) {
      await audit("login.failed", { actor: user._id.toString(), meta: { reason: "bad-password" } });
      return res.status(401).json({ message: "Invalid email or password" }); // uniform
    }

    user.isOnline = true;
    user.lastSeen = new Date();
    await user.save();

    const token = signSessionToken(user._id);

    res.cookie("jwt", token, authCookieSettings());

    try {
      await audit("login", { actor: user._id.toString(), meta: {} });
    } catch { /* non-fatal */ }

    return res.status(200).json({ success: true, user: toSafeUser(user) });
  } catch (error) {
    console.log("Error in login controller", error.message);
    return res.status(500).json({ message: "Internal Server Error" });
  }
}

export async function logout(req, res) {
  try {
    if (req.user) {
      req.user.isOnline = false;
      req.user.lastSeen = new Date();
      await req.user.save();
      await audit("logout", { actor: req.user._id.toString(), meta: {} });
    }
  } catch (error) {
    console.log("Error in logout:", error.message);
  }
  res.clearCookie("jwt");
  return res.status(200).json({ success: true, message: "Logout successful" });
}

export async function onboard(req, res) {
  try {
    const userId = req.user._id;

    const { fullName, bio, nativeLanguage, learningLanguage, location } = req.body;

    if (!fullName || !bio || !nativeLanguage || !learningLanguage || !location) {
      return res.status(400).json({
        message: "All fields are required",
        missingFields: [
          !fullName && "fullName",
          !bio && "bio",
          !nativeLanguage && "nativeLanguage",
          !learningLanguage && "learningLanguage",
          !location && "location",
        ].filter(Boolean),
      });
    }

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      {
        fullName,
        bioEnc: sealField("bio", bio),
        locationEnc: sealField("location", location),
        nativeLanguage,
        learningLanguage,
        profilePic: req.body.profilePic ?? undefined,
        isOnboarded: true,
      },
      { new: true, runValidators: true }
    );

    if (!updatedUser) return res.status(404).json({ message: "User not found" });

    try {
      await upsertStreamUser({
        id: updatedUser._id.toString(),
        name: updatedUser.fullName,
        image: updatedUser.profilePic || "",
      });
      console.log(`Stream user updated after onboarding for ${updatedUser.fullName}`);
    } catch (streamError) {
      console.log("Error updating Stream user during onboarding:", streamError.message);
    }

    try {
      await audit("onboard", { actor: updatedUser._id.toString(), meta: {} });
    } catch { /* skip */ }

    return res.status(200).json({ success: true, user: toSafeUser(updatedUser) });
  } catch (error) {
    console.error("Onboarding error:", error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
}

export async function updateProfile(req, res) {
  try {
    const userId = req.user._id;
    const { fullName, bio, nativeLanguage, learningLanguage, location, profilePic, currentPassword, newPassword } = req.body;

    const user = await User.findById(userId).select("+password");

    if (!user) return res.status(404).json({ message: "User not found" });

    if (fullName !== undefined) user.fullName = fullName;
    if (nativeLanguage !== undefined) user.nativeLanguage = nativeLanguage;
    if (learningLanguage !== undefined) user.learningLanguage = learningLanguage;

    // sensitive fields stay encrypted at rest
    if (bio !== undefined) user.bioEnc = sealField("bio", bio);
    if (location !== undefined) user.locationEnc = sealField("location", location);
    if (profilePic !== undefined) user.profilePic = profilePic;

    if (newPassword) {
      if (!currentPassword) {
        return res.status(400).json({ message: "Current password is required" });
      }
      if (newPassword.length < 6) {
        return res.status(400).json({ message: "Password must be at least 6 characters" });
      }
      if (!/[a-zA-Z]/.test(newPassword) || !/[0-9]/.test(newPassword)) {
        return res.status(400).json({
          message: "Password must contain at least one letter and one number",
        });
      }
      const isMatch = await user.matchPassword(currentPassword);
      if (!isMatch) {
        await audit("profile.password-change-failed", { actor: userId.toString(), meta: {} });
        return res.status(400).json({ message: "Current password is incorrect" });
      }
      user.password = newPassword;
    }

    await user.save();

    try {
      await upsertStreamUser({
        id: user._id.toString(),
        name: user.fullName,
        image: user.profilePic || "",
      });
    } catch (streamError) {
      console.log("Error updating Stream user:", streamError.message);
    }

    if (newPassword) {
      await audit("profile.password-changed", { actor: user._id.toString(), meta: {} });
    }
    await audit("profile.updated", { actor: user._id.toString(), meta: {} });

    const updatedUser = await User.findById(userId);
    return res.status(200).json({ success: true, user: toSafeUser(updatedUser) });
  } catch (error) {
    console.error("Error updating profile:", error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
}
