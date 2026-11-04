import { useEffect, useRef, useState } from "react";
import toast from "react-hot-toast";
import {
  addGroupMembers,
  deleteGroup,
  removeGroupMember,
  setGroupAdmin,
  updateGroup,
  uploadGroupImage,
} from "../lib/api";
import AvatarImage from "./AvatarImage";
import { generateAvatar } from "../lib/utils";
import {
  CrownIcon,
  ImagePlusIcon,
  LoaderIcon,
  LockIcon,
  PlusIcon,
  SaveIcon,
  ShieldCheckIcon,
  ShieldOffIcon,
  Trash2Icon,
  UnlockIcon,
  UserMinusIcon,
  UsersIcon,
  XIcon,
} from "lucide-react";

const GroupInfoModal = ({
  open,
  onClose,
  channel,
  authUser,
  friends,
  onChanged,
  onDeleted,
}) => {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [addIds, setAddIds] = useState([]);
  const [busy, setBusy] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [, setVersion] = useState(0);
  const imageInputRef = useRef(null);

  useEffect(() => {
    if (open && channel) {
      setName(channel.data?.name || "");
      setDescription(channel.data?.description || "");
      setAddIds([]);
      setConfirmDelete(false);
    }
  }, [open, channel]);

  if (!open || !channel) return null;

  const data = channel.data || {};
  const groupImage =
    data.image || generateAvatar(data.name || "Group", (data.name || "Group").length + 9);
  const ownerId = data.owner || data.created_by_id || data.created_by?.id;
  const admins = Array.isArray(data.admins) ? data.admins : [];
  const isOwner = ownerId === authUser?._id;
  const isAdmin = isOwner || admins.includes(authUser?._id);
  const muted = Boolean(data.group_muted || data.muted);

  const members = Object.values(channel.state.members || {}).filter((m) => m.user_id);
  const memberIds = new Set(members.map((m) => m.user_id));
  const candidates = friends.filter((f) => !memberIds.has(f._id));

  const refresh = async () => {
    try {
      await channel.watch();
    } catch {}
    setVersion((v) => v + 1);
    await onChanged?.();
  };

  const run = async (fn, successMessage) => {
    setBusy(true);
    try {
      await fn();
      if (successMessage) toast.success(successMessage);
      await refresh();
    } catch (error) {
      toast.error(error.response?.data?.message || error.message || "Action failed");
    } finally {
      setBusy(false);
    }
  };

  const handleRename = () => {
    if (!name.trim()) {
      toast.error("Group name cannot be empty");
      return;
    }
    run(() => updateGroup(channel.id, { name: name.trim() }), "Group renamed");
  };

  const handleMute = () => {
    run(
      () => updateGroup(channel.id, { muted: !muted }),
      muted ? "Members can send messages again" : "Only admins can send messages now"
    );
  };

  const handleSaveDescription = () => {
    run(
      () => updateGroup(channel.id, { description: description.trim() }),
      "Group description updated"
    );
  };

  const handleImageUpload = async (e) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    if (!file.type.startsWith("image/")) {
      toast.error("Please select an image file");
      return;
    }

    setUploading(true);
    try {
      await uploadGroupImage(channel.id, file);
      toast.success("Group photo updated");
      await refresh();
    } catch (error) {
      toast.error(error.response?.data?.message || "Failed to upload group photo");
    } finally {
      setUploading(false);
    }
  };

  const handleRemoveImage = () => {
    run(() => updateGroup(channel.id, { image: "" }), "Group photo removed");
  };

  const handleAdd = () => {
    if (addIds.length === 0) return;
    run(async () => {
      await addGroupMembers(channel.id, addIds);
      setAddIds([]);
    }, "Members added");
  };

  const handlePromote = (userId) => {
    run(() => setGroupAdmin(channel.id, userId, "promote"), "Promoted to admin");
  };

  const handleDemote = (userId) => {
    run(() => setGroupAdmin(channel.id, userId, "demote"), "Admin role removed");
  };

  const handleRemove = (userId) => {
    run(() => removeGroupMember(channel.id, userId), "Member removed");
  };

  const handleDelete = () => {
    setBusy(true);
    deleteGroup(channel.id)
      .then(() => {
        toast.success("Group deleted");
        onClose?.();
        onDeleted?.();
      })
      .catch((error) => {
        toast.error(error.response?.data?.message || "Failed to delete group");
      })
      .finally(() => setBusy(false));
  };

  const toggleAdd = (id) => {
    setAddIds((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]));
  };

  return (
    <div
      className="fixed inset-0 z-[65] bg-black/60 flex items-center justify-center p-4"
      onClick={onClose}
    >
      <div
        className="bg-base-100 rounded-2xl w-full max-w-lg shadow-2xl modal-pop max-h-[88vh] flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between p-4 border-b border-base-300 shrink-0">
          <h3 className="text-lg font-bold flex items-center gap-2">
            <UsersIcon className="size-5 text-primary" />
            Group info
          </h3>
          <button className="btn btn-ghost btn-sm btn-circle" onClick={onClose}>
            <XIcon className="size-5" />
          </button>
        </div>

        <div className="p-4 overflow-y-auto no-scrollbar space-y-5">
          <div className="flex flex-col items-center gap-3">
            <div className="avatar">
              <div className="w-24 h-24 rounded-2xl overflow-hidden ring-2 ring-base-300">
                <AvatarImage
                  src={groupImage}
                  alt={data.name || "Group"}
                  name={data.name || "Group"}
                  className="w-full h-full object-cover"
                />
              </div>
            </div>
            {isAdmin && (
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  className="btn btn-outline btn-xs gap-1"
                  onClick={() => imageInputRef.current?.click()}
                  disabled={busy || uploading}
                >
                  {uploading ? (
                    <LoaderIcon className="size-3.5 animate-spin" />
                  ) : (
                    <ImagePlusIcon className="size-3.5" />
                  )}
                  {data.image ? "Change photo" : "Add photo"}
                </button>
                {data.image && (
                  <button
                    type="button"
                    className="btn btn-ghost btn-xs text-error gap-1"
                    onClick={handleRemoveImage}
                    disabled={busy || uploading}
                  >
                    <Trash2Icon className="size-3.5" />
                    Remove
                  </button>
                )}
                <input
                  ref={imageInputRef}
                  type="file"
                  accept="image/*"
                  className="hidden"
                  onChange={handleImageUpload}
                />
              </div>
            )}
          </div>

          <div>
            <label className="label py-1">
              <span className="label-text text-xs font-semibold uppercase opacity-60">Group name</span>
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                disabled={!isAdmin || busy}
                className="input input-bordered input-sm flex-1"
              />
              {isAdmin && (
                <button
                  className="btn btn-primary btn-sm gap-1"
                  onClick={handleRename}
                  disabled={busy || !name.trim() || name.trim() === data.name}
                >
                  <SaveIcon className="size-4" />
                  Save
                </button>
              )}
            </div>
          </div>

          <div>
            <label className="label py-1">
              <span className="label-text text-xs font-semibold uppercase opacity-60">
                Group description
              </span>
            </label>
            {isAdmin ? (
              <>
                <textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  maxLength={500}
                  placeholder="What is this group about?"
                  disabled={busy || uploading}
                  className="textarea textarea-bordered textarea-sm w-full h-20"
                />
                <div className="flex items-center justify-between gap-2 mt-1">
                  <span className="text-[11px] opacity-50">{description.length}/500</span>
                  <button
                    className="btn btn-primary btn-xs gap-1"
                    onClick={handleSaveDescription}
                    disabled={
                      busy ||
                      uploading ||
                      description.trim() === (data.description || "").trim()
                    }
                  >
                    <SaveIcon className="size-3.5" />
                    Save description
                  </button>
                </div>
              </>
            ) : (
              <p className="text-sm opacity-70 whitespace-pre-wrap break-words">
                {data.description || "No description yet"}
              </p>
            )}
          </div>

          {isAdmin && (
            <div className="flex items-center justify-between rounded-xl border border-base-300 p-3">
              <div className="flex items-center gap-2">
                {muted ? (
                  <LockIcon className="size-5 text-warning" />
                ) : (
                  <UnlockIcon className="size-5 text-success" />
                )}
                <div>
                  <p className="font-medium text-sm">Only admins can send messages</p>
                  <p className="text-xs opacity-60">
                    {muted ? "Members are muted" : "All members can chat"}
                  </p>
                </div>
              </div>
              <input
                type="checkbox"
                className="toggle toggle-warning toggle-sm"
                checked={muted}
                onChange={handleMute}
                disabled={busy}
              />
            </div>
          )}

          <div>
            <div className="flex items-center justify-between mb-2">
              <p className="text-sm font-semibold">
                Members ({members.length})
              </p>
              <span className="text-xs opacity-60">
                {isOwner ? "You are the owner" : isAdmin ? "You are an admin" : "Member"}
              </span>
            </div>
            <div className="space-y-1">
              {members.map((member) => {
                const uid = member.user_id;
                const user = member.user || {};
                const isMemberOwner = uid === ownerId;
                const isMemberAdmin = admins.includes(uid);
                const canRemove =
                  uid !== ownerId &&
                  (isOwner || (isAdmin && !isMemberAdmin));
                return (
                  <div
                    key={uid}
                    className="flex items-center gap-3 p-2 rounded-lg hover:bg-base-200 transition-colors"
                  >
                    <div className="avatar size-9">
                      <AvatarImage
                        src={user.image}
                        alt={user.name || uid}
                        name={user.name || uid}
                        className="rounded-full w-full h-full object-cover"
                      />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium truncate">
                        {user.name || uid}
                        {uid === authUser?._id && (
                          <span className="text-xs opacity-60"> (you)</span>
                        )}
                      </p>
                      <div className="flex items-center gap-1">
                        {isMemberOwner && (
                          <span className="badge badge-primary badge-xs gap-1">
                            <CrownIcon className="size-3" /> Owner
                          </span>
                        )}
                        {!isMemberOwner && isMemberAdmin && (
                          <span className="badge badge-secondary badge-xs gap-1">
                            <ShieldCheckIcon className="size-3" /> Admin
                          </span>
                        )}
                        {!isMemberOwner && !isMemberAdmin && (
                          <span className="text-[11px] opacity-50">Member</span>
                        )}
                      </div>
                    </div>

                    {isOwner && !isMemberOwner && (
                      <>
                        {isMemberAdmin ? (
                          <button
                            className="btn btn-ghost btn-xs gap-1"
                            onClick={() => handleDemote(uid)}
                            disabled={busy}
                            title="Remove admin role"
                          >
                            <ShieldOffIcon className="size-4" />
                          </button>
                        ) : (
                          <button
                            className="btn btn-ghost btn-xs gap-1"
                            onClick={() => handlePromote(uid)}
                            disabled={busy}
                            title="Make admin"
                          >
                            <ShieldCheckIcon className="size-4" />
                          </button>
                        )}
                      </>
                    )}

                    {canRemove && (
                      <button
                        className="btn btn-ghost btn-xs text-error"
                        onClick={() => handleRemove(uid)}
                        disabled={busy}
                        title="Remove from group"
                      >
                        <UserMinusIcon className="size-4" />
                      </button>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {isAdmin && (
            <div>
              <p className="text-sm font-semibold mb-2 flex items-center gap-1">
                <PlusIcon className="size-4" /> Add friends to group
              </p>
              {candidates.length === 0 ? (
                <p className="text-xs opacity-60">
                  All your friends are already in this group.
                </p>
              ) : (
                <div className="space-y-1 max-h-40 overflow-y-auto no-scrollbar border border-base-300 rounded-lg p-2">
                  {candidates.map((f) => (
                    <label
                      key={f._id}
                      className="flex items-center gap-2 p-1.5 rounded hover:bg-base-200 cursor-pointer"
                    >
                      <input
                        type="checkbox"
                        className="checkbox checkbox-primary checkbox-xs"
                        checked={addIds.includes(f._id)}
                        onChange={() => toggleAdd(f._id)}
                      />
                      <div className="avatar size-7">
                        <AvatarImage
                          src={f.profilePic}
                          alt={f.fullName}
                          name={f.fullName}
                          className="rounded-full w-full h-full object-cover"
                        />
                      </div>
                      <span className="text-sm truncate">{f.fullName}</span>
                    </label>
                  ))}
                </div>
              )}
              <button
                className="btn btn-primary btn-sm w-full mt-2 gap-1"
                onClick={handleAdd}
                disabled={busy || addIds.length === 0}
              >
                {busy ? <LoaderIcon className="size-4 animate-spin" /> : <PlusIcon className="size-4" />}
                Add selected ({addIds.length})
              </button>
            </div>
          )}

          {isAdmin && (
            <div className="border-t border-base-300 pt-4">
              {confirmDelete ? (
                <div className="rounded-xl border border-error/40 bg-error/10 p-3">
                  <p className="text-sm font-semibold mb-1">Delete this group?</p>
                  <p className="text-xs opacity-70 mb-3">
                    This deletes the group and all its messages for every member. This cannot
                    be undone.
                  </p>
                  <div className="flex gap-2">
                    <button
                      className="btn btn-ghost btn-sm flex-1"
                      onClick={() => setConfirmDelete(false)}
                      disabled={busy}
                    >
                      Cancel
                    </button>
                    <button
                      className="btn btn-error btn-sm flex-1"
                      onClick={handleDelete}
                      disabled={busy}
                    >
                      {busy ? "Deleting..." : "Delete group"}
                    </button>
                  </div>
                </div>
              ) : (
                <button
                  className="btn btn-outline btn-error btn-sm w-full gap-1"
                  onClick={() => setConfirmDelete(true)}
                  disabled={busy}
                >
                  <Trash2Icon className="size-4" />
                  Delete group
                </button>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default GroupInfoModal;
