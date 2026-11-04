import useNetworkStatus from "../hooks/useNetworkStatus";
import { WifiOffIcon } from "lucide-react";

const OfflineBanner = () => {
  const online = useNetworkStatus();

  if (online) return null;

  return (
    <div className="fixed top-16 inset-x-0 z-[60] flex justify-center pointer-events-none">
      <div className="bg-warning text-warning-content px-4 py-1.5 rounded-b-xl shadow-lg text-sm font-medium flex items-center gap-2 slide-down">
        <WifiOffIcon className="size-4" />
        You are offline — actions will fail until the connection returns
      </div>
    </div>
  );
};

export default OfflineBanner;
