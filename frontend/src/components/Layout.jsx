import { useEffect, useState } from "react";
import { useLocation } from "react-router";
import Sidebar from "./Sidebar";
import Navbar from "./Navbar";
import MobileNav from "./MobileNav";
import OfflineBanner from "./OfflineBanner";

const Layout = ({ children, showSidebar = false }) => {
  const location = useLocation();
  const isChatArea =
    location.pathname.startsWith("/friends") || location.pathname.startsWith("/chat");

  const [sidebarOpen, setSidebarOpen] = useState(() => {
    try {
      return localStorage.getItem("appSidebarOpen") !== "0";
    } catch {
      return true;
    }
  });

  useEffect(() => {
    try {
      localStorage.setItem("appSidebarOpen", sidebarOpen ? "1" : "0");
    } catch {}
  }, [sidebarOpen]);

  return (
    <div className="h-screen overflow-hidden">
      <OfflineBanner />
      <div className="flex h-full">
        {showSidebar && sidebarOpen && <Sidebar onCollapse={() => setSidebarOpen(false)} />}

        <div className="flex-1 flex flex-col min-w-0 h-full">
          <Navbar
            onOpenSidebar={
              showSidebar && !sidebarOpen ? () => setSidebarOpen(true) : undefined
            }
          />

          <main
            className={`flex-1 min-h-0 pb-16 lg:pb-0 ${
              isChatArea ? "overflow-hidden" : "overflow-y-auto"
            }`}
          >
            {children}
          </main>
        </div>
      </div>
      <MobileNav />
    </div>
  );
};
export default Layout;
