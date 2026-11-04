import mongoose from "mongoose";
import "dotenv/config";
import User from "./src/models/User.js";
import { sealField, emailLookupHash } from "./src/lib/crypto/dbcrypto.js";
import { loadMasterKey } from "./src/lib/crypto/keys.js";

const users = [
  {
    fullName: "Ahmed Hassan",
    email: "ahmed@test.com",
    password: "123456",
    bio: "Egyptian Arabic speaker looking to improve my English",
    nativeLanguage: "arabic",
    learningLanguage: "english",
    location: "Cairo, Egypt",
  },
  {
    fullName: "Sofia Martinez",
    email: "sofia@test.com",
    password: "123456",
    bio: "Native Spanish speaker from Mexico, learning English",
    nativeLanguage: "spanish",
    learningLanguage: "english",
    location: "Mexico City, Mexico",
  },
  {
    fullName: "Jean-Pierre Dubois",
    email: "jean@test.com",
    password: "123456",
    bio: "French native, practicing Spanish for travel",
    nativeLanguage: "french",
    learningLanguage: "spanish",
    location: "Paris, France",
  },
  {
    fullName: "Hiroshi Tanaka",
    email: "hiroshi@test.com",
    password: "123456",
    bio: "Japanese speaker learning English and French",
    nativeLanguage: "japanese",
    learningLanguage: "english",
    location: "Tokyo, Japan",
  },
  {
    fullName: "Maria Schmidt",
    email: "maria@test.com",
    password: "123456",
    bio: "German native, learning French for work",
    nativeLanguage: "german",
    learningLanguage: "french",
    location: "Berlin, Germany",
  },
  {
    fullName: "John Smith",
    email: "john@test.com",
    password: "123456",
    bio: "American looking for Arabic language partners",
    nativeLanguage: "english",
    learningLanguage: "arabic",
    location: "New York, USA",
  },
];

async function seed() {
  try {
    // make sure the master key (encryption at rest) is loaded
    loadMasterKey();

    await mongoose.connect(process.env.MONGO_URI);
    console.log("Connected to MongoDB");

    const existing = await User.countDocuments();
    if (existing > 1) {
      console.log(`Database already has ${existing} users. Skipping seed.`);
      await mongoose.disconnect();
      return;
    }

    for (const user of users) {
      const idx = Math.floor(Math.random() * 100) + 1;
      // fields that contain sensitive data are stored encrypted at rest
      await User.create({
        fullName: user.fullName,
        emailHmac: emailLookupHash(user.email),
        emailEnc: sealField("email", user.email),
        password: user.password,
        bioEnc: sealField("bio", user.bio),
        locationEnc: sealField("location", user.location),
        nativeLanguage: user.nativeLanguage,
        learningLanguage: user.learningLanguage,
        isOnboarded: true,
        profilePic: `https://avatar.iran.liara.run/public/${idx}.png`,
      });
      console.log(`Created user: ${user.fullName}`);
    }

    console.log("\nSeed complete! You can login with any email and password: 123456");
    await mongoose.disconnect();
  } catch (error) {
    console.error("Seed error:", error);
    process.exit(1);
  }
}

seed();
