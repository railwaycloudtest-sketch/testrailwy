import { useMutation } from "@tanstack/react-query";
import { useNavigate } from "react-router";
import toast from "react-hot-toast";
import { signup } from "../lib/api";

const useSignUp = () => {
  const navigate = useNavigate();

  const { mutate, isPending, error } = useMutation({
    mutationFn: signup,
    onSuccess: () => {
      toast.success("Account created successfully. Please sign in.");
      navigate("/login", { replace: true });
    },
  });

  return { isPending, error, signupMutation: mutate };
};
export default useSignUp;
