const palette = [
  "EF4444", "F97316", "EAB308", "22C55E", "14B8A6",
  "3B82F6", "8B5CF6", "EC4899", "06B6D4", "84CC16",
];

function hashSeed(seed) {
  if (typeof seed === "string") {
    let h = 0;
    for (let i = 0; i < seed.length; i++) {
      h = (h * 31 + seed.charCodeAt(i)) >>> 0;
    }
    return h;
  }
  return Math.abs(Number(seed) || 0);
}

export function generateAvatar(name, seed = Date.now()) {
  const initials = (name || "U")
    .trim()
    .split(/\s+/)
    .map((w) => w[0])
    .join("")
    .slice(0, 2)
    .toUpperCase() || "U";

  const color = palette[hashSeed(seed) % palette.length];

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128"><rect width="100%" height="100%" fill="#${color}"/><text x="50%" y="54%" dominant-baseline="middle" text-anchor="middle" font-family="system-ui,-apple-system,sans-serif" font-size="52" font-weight="700" fill="rgba(255,255,255,0.95)">${initials}</text></svg>`;

  return "data:image/svg+xml," + encodeURIComponent(svg);
}
