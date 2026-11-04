export const capitialize = (str) => str.charAt(0).toUpperCase() + str.slice(1);

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

export const generateAvatar = (name, seed = Date.now()) => {
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
};

const pad = (n) => String(n).padStart(2, "0");

export const formatLastSeen = (lastSeen) => {
  if (!lastSeen) return "Offline";

  const now = new Date();
  const then = new Date(lastSeen);
  if (isNaN(then.getTime())) return "Offline";

  const diffMs = now.getTime() - then.getTime();
  const diffSec = Math.floor(diffMs / 1000);
  const timeStr = `${pad(then.getHours())}:${pad(then.getMinutes())}`;

  if (diffSec < 60) return "Last seen just now";

  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `Last seen ${diffMin} min ago`;

  const isToday = now.toDateString() === then.toDateString();
  if (isToday) return `Last seen today at ${timeStr}`;

  const yesterday = new Date(now);
  yesterday.setDate(now.getDate() - 1);
  if (yesterday.toDateString() === then.toDateString()) {
    return `Last seen yesterday at ${timeStr}`;
  }

  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24 && !isToday) {
    return `Last seen today at ${timeStr}`;
  }

  const dateStr = `${pad(then.getDate())}/${pad(then.getMonth() + 1)}/${then.getFullYear()}`;
  return `Last seen ${dateStr} at ${timeStr}`;
};

export const formatChatTime = (timestamp) => {
  if (!timestamp) return "";
  const then = new Date(timestamp);
  if (isNaN(then.getTime())) return "";

  const now = new Date();
  const diffMin = Math.floor((now.getTime() - then.getTime()) / 60000);

  if (diffMin < 1) return "now";
  if (diffMin < 60) return `${diffMin}m`;

  const isToday = now.toDateString() === then.toDateString();
  if (isToday) {
    return `${pad(then.getHours())}:${pad(then.getMinutes())}`;
  }

  const yesterday = new Date(now);
  yesterday.setDate(now.getDate() - 1);
  if (yesterday.toDateString() === then.toDateString()) {
    return "Yesterday";
  }

  return `${pad(then.getDate())}/${pad(then.getMonth() + 1)}/${then.getFullYear()}`;
};
