import { Link, useLocation } from "react-router";
import useAuthUser from "../hooks/useAuthUser";
import AvatarImage from "./AvatarImage";
import {
  BellIcon,
  HomeIcon,
  PanelLeftCloseIcon,
  SettingsIcon,
  ShipWheelIcon,
  UsersIcon,
} from "lucide-react";

const Sidebar = ({ onCollapse }) => {
  const { authUser } = useAuthUser();
  const location = useLocation();
  const currentPath = location.pathname;

  return (
    <aside className="w-64 bg-base-200 border-r border-base-300 hidden lg:flex flex-col h-full shrink-0">
      <div className="p-4 border-b border-base-300 flex items-center gap-2">
        <Link to="/" className="flex items-center gap-2.5 flex-1 min-w-0">
          <ShipWheelIcon className="size-8 text-primary shrink-0" />
          <span className="text-2xl font-bold font-mono bg-clip-text text-transparent bg-gradient-to-r from-primary to-secondary tracking-wider truncate">
            Streamify
          </span>
        </Link>
        <button
          className="btn btn-ghost btn-sm btn-circle shrink-0"
          onClick={onCollapse}
          title="Close sidebar"
        >
          <PanelLeftCloseIcon className="size-4" />
        </button>
      </div>

      <nav className="flex-1 p-4 space-y-1">
        <Link
          to="/"
          className={`btn btn-ghost justify-start w-full gap-3 px-3 normal-case ${
            currentPath === "/" ? "btn-active" : ""
          }`}
        >
          <HomeIcon className="size-5 text-base-content opacity-70" />
          <span>Home</span>
        </Link>

        <Link
          to="/friends"
          className={`btn btn-ghost justify-start w-full gap-3 px-3 normal-case ${
            currentPath === "/friends" ? "btn-active" : ""
          }`}
        >
          <UsersIcon className="size-5 text-base-content opacity-70" />
          <span>Friends</span>
        </Link>

        <Link
          to="/notifications"
          className={`btn btn-ghost justify-start w-full gap-3 px-3 normal-case ${
            currentPath === "/notifications" ? "btn-active" : ""
          }`}
        >
          <BellIcon className="size-5 text-base-content opacity-70" />
          <span>Notifications</span>
        </Link>
      </nav>

      <div className="p-4 border-t border-base-300 mt-auto">
        <Link to="/settings" className="flex items-center gap-3 hover:opacity-80 transition-opacity">
          <div className="avatar">
            <div className="w-10 rounded-full">
              <AvatarImage src={authUser?.profilePic} alt="User Avatar" name={authUser?.fullName} />
            </div>
          </div>
          <div className="flex-1 min-w-0">
            <p className="font-semibold text-sm truncate">{authUser?.fullName}</p>
            <p className="text-xs text-success flex items-center gap-1">
              <span className="size-2 rounded-full bg-success inline-block" />
              Online
            </p>
          </div>
          <SettingsIcon className="size-4 opacity-50" />
        </Link>
      </div>
    </aside>
  );
};
export default Sidebar;
