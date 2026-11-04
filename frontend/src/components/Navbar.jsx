import { Link, useLocation } from "react-router";
import useAuthUser from "../hooks/useAuthUser";
import useNotifications from "../hooks/useNotifications";
import { BellIcon, LogOutIcon, PanelLeftOpenIcon, ShipWheelIcon } from "lucide-react";
import ThemeSelector from "./ThemeSelector";
import AvatarImage from "./AvatarImage";
import useLogout from "../hooks/useLogout";

const Navbar = ({ onOpenSidebar }) => {
  const { authUser } = useAuthUser();
  const location = useLocation();
  const isChatPage = location.pathname?.startsWith("/chat");
  const { unreadCount } = useNotifications();

  const { logoutMutation } = useLogout();

  return (
    <nav className="bg-base-200 border-b border-base-300 sticky top-0 z-30 h-16 flex items-center shrink-0">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8 w-full">
        <div className="flex items-center justify-end w-full gap-2 sm:gap-4">
          {onOpenSidebar && (
            <button
              className="btn btn-ghost btn-circle mr-auto hidden lg:inline-flex"
              onClick={onOpenSidebar}
              title="Open sidebar"
            >
              <PanelLeftOpenIcon className="h-6 w-6 opacity-70" />
            </button>
          )}
          {isChatPage && (
            <div className="mr-auto">
              <Link to="/" className="flex items-center gap-2.5">
                <ShipWheelIcon className="size-8 sm:size-9 text-primary" />
                <span className="text-2xl sm:text-3xl font-bold font-mono bg-clip-text text-transparent bg-gradient-to-r from-primary to-secondary tracking-wider">
                  Streamify
                </span>
              </Link>
            </div>
          )}

          <Link to="/notifications" className="relative">
            <button
              className={`btn btn-ghost btn-circle ${
                unreadCount > 0 ? "text-primary" : ""
              }`}
            >
              <BellIcon className="h-6 w-6 opacity-70" />
            </button>
            {unreadCount > 0 && (
              <span className="absolute -top-1 -right-1 size-5 rounded-full bg-red-500 text-white text-[10px] font-bold flex items-center justify-center badge-pop shadow-lg">
                {unreadCount > 9 ? "9+" : unreadCount}
              </span>
            )}
          </Link>

          <ThemeSelector />

          <Link to="/settings" className="avatar hover:opacity-80 transition-opacity">
            <div className="w-9 rounded-full border border-base-300/50 hover:border-primary transition-colors cursor-pointer">
              <AvatarImage src={authUser?.profilePic} alt={authUser?.fullName} />
            </div>
          </Link>

          <button className="btn btn-ghost btn-circle" onClick={() => logoutMutation()}>
            <LogOutIcon className="h-6 w-6 opacity-70" />
          </button>
        </div>
      </div>
    </nav>
  );
};
export default Navbar;
