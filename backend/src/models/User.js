import mongoose from "mongoose";
import bcrypt from "bcryptjs";

const userSchema = new mongoose.Schema(
  {
    fullName: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      default: undefined,
    },
    /**
     * Email is stored ENCRYPTED AT REST (AES-256-GCM) + a keyed HMAC index for
     * lookups/uniqueness — the plaintext never touches the database.
     */
    emailHmac: {
      type: String,
      required: true,
      unique: true, // replaces plaintext uniqueness on email
    },
    emailEnc: {
      type: String,
      required: true,
    },
    password: {
      type: String,
      required: true,
      minlength: 6,
    },
    /** Sensitive profile data — encrypted at rest (AES-256-GCM). */
    bioEnc: {
      type: String,
      default: "",
    },
    locationEnc: {
      type: String,
      default: "",
    },
    profilePic: {
      type: String,
      default: "",
    },
    nativeLanguage: {
      type: String,
      default: "",
    },
    learningLanguage: {
      type: String,
      default: "",
    },
    /**
     * E2EE public keys published by the CLIENT (never trust these with the
     * ability to decrypt — the private half never leaves user devices):
     *   rsaEncPub → RSA-OAEP-3072  (chat key wrapping, "key exchange")
     *   rsaSigPub → RSA-PSS-3072   (digital signatures, non-repudiation)
     * fingerprint = sha256 of the SPKI — displayed for key-verification.
     */
    publicKeys: {
      rsaEncPub: { type: String, default: "" }, // base64 SPKI
      rsaSigPub: { type: String, default: "" }, // base64 SPKI
      fingerprint: { type: String, default: "" },
    },
    /**
     * Client-encrypted private key bundle (sealed with AES-256-GCM under a key
     * derived from the user's password via PBKDF2-600k). The server cannot
     * open it — enables recovery/login on other devices without weakening E2EE.
     */
    keysBackup: {
      type: String,
      default: "",
    },
    isOnboarded: {
      type: Boolean,
      default: false,
    },
    isOnline: {
      type: Boolean,
      default: false,
    },
    lastSeen: {
      type: Date,
      default: null,
    },
    notificationsViewedAt: {
      type: Date,
      default: null,
    },
    friends: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
      },
    ],
  },
  { timestamps: true }
);

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();

  try {
    // cost 12 (~250ms) — OWASP-recommended default floor; tunable via env.
    const saltRounds = Number(process.env.BCRYPT_COST || 12);
    const salt = await bcrypt.genSalt(saltRounds);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// bcrypt.compare is internally constant-time (safe against timing oracles)
userSchema.methods.matchPassword = async function (enteredPassword) {
  const isPasswordCorrect = await bcrypt.compare(enteredPassword, this.password);
  return isPasswordCorrect;
};

const User = mongoose.model("User", userSchema);

export default User;
