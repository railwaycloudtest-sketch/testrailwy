import { useState, useRef } from "react";
import useAuthUser from "../hooks/useAuthUser";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import toast from "react-hot-toast";
import { updateProfile, uploadProfilePic } from "../lib/api";
import { generateAvatar } from "../lib/utils";
import { LANGUAGES } from "../constants";
import { resealIdentityBackup } from "../lib/crypto/vault";
import { CameraIcon, EyeIcon, EyeOffIcon, LoaderIcon, SaveIcon, ShuffleIcon, UploadIcon } from "lucide-react";

const SettingsPage = () => {
  const { authUser } = useAuthUser();
  const queryClient = useQueryClient();
  const fileInputRef = useRef(null);

  const [form, setForm] = useState({
    fullName: authUser?.fullName || "",
    bio: authUser?.bio || "",
    nativeLanguage: authUser?.nativeLanguage || "",
    learningLanguage: authUser?.learningLanguage || "",
    location: authUser?.location || "",
    profilePic: authUser?.profilePic || "",
    currentPassword: "",
    newPassword: "",
    confirmPassword: "",
  });

  const [uploading, setUploading] = useState(false);
  const [visiblePasswords, setVisiblePasswords] = useState({
    current: false,
    new: false,
    confirm: false,
  });

  const togglePassword = (key) =>
    setVisiblePasswords((prev) => ({ ...prev, [key]: !prev[key] }));

  const { mutate: saveMutation, isPending } = useMutation({
    mutationFn: updateProfile,
    onSuccess: (_data, variables) => {
      toast.success("Profile updated successfully");
      // Password changed → re-seal the E2EE identity backup under the new
      // password so the next unlock works (key material itself is unchanged).
      if (variables?.newPassword) {
        resealIdentityBackup(variables.newPassword).catch((error) => {
          console.error("E2EE identity reseal failed:", error);
          toast.error("Password changed, but your encryption keys could not be re-locked. Contact support if login issues occur.");
        });
      }
      queryClient.invalidateQueries({ queryKey: ["authUser"] });
      setForm((prev) => ({ ...prev, currentPassword: "", newPassword: "", confirmPassword: "" }));
    },
    onError: (error) => {
      toast.error(error.response?.data?.message || "Failed to update profile");
    },
  });

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleRandomAvatar = () => {
    const name = form.fullName?.trim() || authUser?.fullName || "User";
    const url = generateAvatar(name, Math.floor(Math.random() * 100000));
    setForm({ ...form, profilePic: url });
    toast.success("Random avatar generated!");
  };

  const handleFileUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (!file.type.startsWith("image/")) {
      toast.error("Please select an image file");
      return;
    }

    setUploading(true);
    try {
      const data = await uploadProfilePic(file);
      setForm({ ...form, profilePic: data.url });
      toast.success("Image uploaded!");
    } catch (error) {
      toast.error(error.response?.data?.message || "Failed to upload image");
    } finally {
      setUploading(false);
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();

    if (form.newPassword && form.newPassword.length < 6) {
      toast.error("Password must be at least 6 characters");
      return;
    }

    if (form.newPassword && !(/[a-zA-Z]/.test(form.newPassword) && /[0-9]/.test(form.newPassword))) {
      toast.error("Password must contain at least one letter and one number");
      return;
    }

    if (form.newPassword && !form.currentPassword) {
      toast.error("Please enter your current password");
      return;
    }

    if (form.newPassword && form.newPassword !== form.confirmPassword) {
      toast.error("Passwords do not match");
      return;
    }

    const payload = {
      fullName: form.fullName,
      bio: form.bio,
      nativeLanguage: form.nativeLanguage,
      learningLanguage: form.learningLanguage,
      location: form.location,
      profilePic: form.profilePic,
    };

    if (form.newPassword) {
      payload.currentPassword = form.currentPassword;
      payload.newPassword = form.newPassword;
    }

    saveMutation(payload);
  };

  return (
    <div className="p-4 sm:p-6 lg:p-8 max-w-2xl mx-auto">
      <h1 className="text-2xl sm:text-3xl font-bold mb-8">Settings</h1>

      <form onSubmit={handleSubmit} className="space-y-6">
        <div className="flex flex-col items-center gap-4 mb-6">
          <div className="size-28 rounded-full bg-base-300 overflow-hidden">
            {form.profilePic ? (
              <img src={form.profilePic} alt="Profile" className="w-full h-full object-cover" />
            ) : (
              <div className="flex items-center justify-center h-full">
                <CameraIcon className="size-10 opacity-40" />
              </div>
            )}
          </div>

          <div className="flex gap-2">
            <button type="button" onClick={handleRandomAvatar} className="btn btn-accent btn-sm">
              <ShuffleIcon className="size-4" />
              Random
            </button>
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              className="btn btn-outline btn-sm"
              disabled={uploading}
            >
              {uploading ? (
                <LoaderIcon className="size-4 animate-spin" />
              ) : (
                <UploadIcon className="size-4" />
              )}
              Upload
            </button>
            <input
              ref={fileInputRef}
              type="file"
              accept="image/*"
              className="hidden"
              onChange={handleFileUpload}
            />
          </div>
        </div>

        <div className="form-control">
          <label className="label"><span className="label-text">Full Name</span></label>
          <input
            type="text" name="fullName" value={form.fullName}
            onChange={handleChange} className="input input-bordered w-full"
          />
        </div>

        <div className="form-control">
          <label className="label"><span className="label-text">Bio</span></label>
          <textarea
            name="bio" value={form.bio} onChange={handleChange}
            className="textarea textarea-bordered h-24"
          />
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="form-control">
            <label className="label"><span className="label-text">Native Language</span></label>
            <select name="nativeLanguage" value={form.nativeLanguage} onChange={handleChange} className="select select-bordered w-full">
              <option value="">Select</option>
              {LANGUAGES.map((l) => <option key={l} value={l.toLowerCase()}>{l}</option>)}
            </select>
          </div>
          <div className="form-control">
            <label className="label"><span className="label-text">Learning Language</span></label>
            <select name="learningLanguage" value={form.learningLanguage} onChange={handleChange} className="select select-bordered w-full">
              <option value="">Select</option>
              {LANGUAGES.map((l) => <option key={l} value={l.toLowerCase()}>{l}</option>)}
            </select>
          </div>
        </div>

        <div className="form-control">
          <label className="label"><span className="label-text">Location</span></label>
          <input
            type="text" name="location" value={form.location}
            onChange={handleChange} className="input input-bordered w-full"
            placeholder="City, Country"
          />
        </div>

        <div className="divider">Change Password (optional)</div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="form-control">
            <label className="label"><span className="label-text">Current Password</span></label>
            <div className="relative">
              <input
                type={visiblePasswords.current ? "text" : "password"}
                name="currentPassword" value={form.currentPassword}
                onChange={handleChange} className="input input-bordered w-full pr-12"
                autoComplete="current-password"
              />
              <button
                type="button"
                onClick={() => togglePassword("current")}
                className="absolute right-3 top-1/2 -translate-y-1/2 opacity-60 hover:opacity-100 transition-opacity"
                aria-label={visiblePasswords.current ? "Hide password" : "Show password"}
              >
                {visiblePasswords.current ? <EyeOffIcon className="size-5" /> : <EyeIcon className="size-5" />}
              </button>
            </div>
          </div>
          <div className="form-control">
            <label className="label"><span className="label-text">New Password</span></label>
            <div className="relative">
              <input
                type={visiblePasswords.new ? "text" : "password"}
                name="newPassword" value={form.newPassword}
                onChange={handleChange} className="input input-bordered w-full pr-12"
                autoComplete="new-password"
              />
              <button
                type="button"
                onClick={() => togglePassword("new")}
                className="absolute right-3 top-1/2 -translate-y-1/2 opacity-60 hover:opacity-100 transition-opacity"
                aria-label={visiblePasswords.new ? "Hide password" : "Show password"}
              >
                {visiblePasswords.new ? <EyeOffIcon className="size-5" /> : <EyeIcon className="size-5" />}
              </button>
            </div>
          </div>
        </div>

        {form.newPassword && (
          <div className="form-control">
            <label className="label"><span className="label-text">Confirm New Password</span></label>
            <div className="relative">
              <input
                type={visiblePasswords.confirm ? "text" : "password"}
                name="confirmPassword" value={form.confirmPassword}
                onChange={handleChange} className="input input-bordered w-full pr-12"
                autoComplete="new-password"
              />
              <button
                type="button"
                onClick={() => togglePassword("confirm")}
                className="absolute right-3 top-1/2 -translate-y-1/2 opacity-60 hover:opacity-100 transition-opacity"
                aria-label={visiblePasswords.confirm ? "Hide password" : "Show password"}
              >
                {visiblePasswords.confirm ? <EyeOffIcon className="size-5" /> : <EyeIcon className="size-5" />}
              </button>
            </div>
          </div>
        )}

        <button className="btn btn-primary w-full" disabled={isPending} type="submit">
          {isPending ? (
            <><LoaderIcon className="animate-spin size-5 mr-2" /> Saving...</>
          ) : (
            <><SaveIcon className="size-5 mr-2" /> Save Changes</>
          )}
        </button>
      </form>
    </div>
  );
};

export default SettingsPage;
