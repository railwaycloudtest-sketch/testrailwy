import { useEffect, useState } from "react";
import toast from "react-hot-toast";

const useNetworkStatus = () => {
  const [online, setOnline] = useState(
    typeof navigator === "undefined" ? true : navigator.onLine
  );

  useEffect(() => {
    const handleOnline = () => {
      setOnline(true);
      toast.success("Back online");
    };
    const handleOffline = () => {
      setOnline(false);
      toast.error("You are offline");
    };

    window.addEventListener("online", handleOnline);
    window.addEventListener("offline", handleOffline);
    return () => {
      window.removeEventListener("online", handleOnline);
      window.removeEventListener("offline", handleOffline);
    };
  }, []);

  return online;
};

export default useNetworkStatus;
