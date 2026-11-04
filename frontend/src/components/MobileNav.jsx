import { Link, useLocation } from "react-router";
import useNotifications from "../hooks/useNotifications";
import {
  BellIcon,
  HomeIcon,
  MessageCircleIcon,
  SettingsIcon,
} from "lucide-react";

const MobileNav = () => {
  const location = useLocation();
  const { unreadCount } = useNotifications();

  const item = (to, Icon, hasBadge = false) => {
    const active = location.pathname === to || location.pathname.startsWith(to + "/");
    return (
      <Link
        to={to}
        className={`flex-1 flex flex-col items-center justify-center py-2 relative ${
          active ? "text-primary" : "opacity-60"
        }`}
      >
        <Icon className="size-6" />
        {hasBadge && unreadCount > 0 && (
          <span className="absolute top-1 right-1/4 size-4 rounded-full bg-red-500 text-white text-[9px] font-bold flex items-center justify-center badge-pop">
            {unreadCount > 9 ? "9+" : unreadCount}
          </span>
        )}
      </Link>
    );
  };

  return (
    <nav className="lg:hidden fixed bottom-0 inset-x-0 z-40 bg-base-200 border-t border-base-300 flex items-center pb-[env(safe-area-inset-bottom)]">
      {item("/", HomeIcon)}
      {item("/friends", MessageCircleIcon)}
      {item("/notifications", BellIcon, true)}
      {item("/settings", SettingsIcon)}
    </nav>
  );
};

export default MobileNav;
