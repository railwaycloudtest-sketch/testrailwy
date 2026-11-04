import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router";
import toast from "react-hot-toast";
import { login } from "../lib/api";
import { unlockIdentity } from "../lib/crypto/vault";

const useLogin = () => {
  const queryClient = useQueryClient();
  const navigate = useNavigate();

  const { mutate, isPending, error } = useMutation({
    mutationFn: async ({ loginData, password }) => {
      // password travels only in this closure — the E2EE vault unlock uses it
      // to derive the private-key-wrapping key; the server never receives it.
      const data = await login(loginData);
      if (data?.user?._id) {
        try {
          // E2EE unlock: PBKDF2(600k) → AES-256-GCM on the machine, then
          // session keys (RSA-3072 pairs) materialize in memory only.
          await unlockIdentity(data.user._id, password ?? loginData.password);
        } catch (error) {
          // identity unlocks are non-fatal for the login itself; the user can
          // retry from chat (they'd be shown the "re-enter password" flow).
          if (error?.message === "wrong-password") {
            toast.error("Password correct, but key decryption failed — please retry.");
          } else {
            console.error("E2EE unlock failed:", error);
          }
        }
      }
      return data;
    },
    onSuccess: (data) => {
      queryClient.setQueryData(["authUser"], { success: true, user: data.user });
      queryClient.invalidateQueries({ queryKey: ["authUser"] });
      toast.success("Welcome back!");
      navigate(data.user?.isOnboarded ? "/" : "/onboarding", { replace: true });
    },
  });

  return { error, isPending, loginMutation: (loginData) => mutate({ loginData, password: loginData?.password }) };
};

export default useLogin;
