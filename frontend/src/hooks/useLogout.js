import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router";
import { StreamChat } from "stream-chat";
import toast from "react-hot-toast";
import { logout } from "../lib/api";
import { clearIdentityLock } from "../lib/crypto/vault";

const useLogout = () => {
  const queryClient = useQueryClient();
  const navigate = useNavigate();

  const {
    mutate: logoutMutation,
    isPending,
    error,
  } = useMutation({
    mutationFn: logout,
    onSuccess: () => {
      const apiKey = import.meta.env.VITE_STREAM_API_KEY;
      if (apiKey) {
        const client = StreamChat.getInstance(apiKey);
        if (client.user) client.disconnectUser().catch(() => {});
      }
      // wipe all E2EE state: identity keys, per-channel keys, call keys
      clearIdentityLock();
      try {
        for (const key of Object.keys(sessionStorage)) {
          if (key.startsWith("sm1.")) sessionStorage.removeItem(key);
        }
      } catch {
        /* storage unavailable — stay silent */
      }
      queryClient.setQueryData(["authUser"], null);
      queryClient.removeQueries({
        predicate: (query) => query.queryKey[0] !== "authUser",
      });
      toast.success("Logged out");
      navigate("/login", { replace: true });
    },
    onError: () => {
      toast.error("Could not log out. Please try again.");
    },
  });

  return { logoutMutation, isPending, error };
};
export default useLogout;
