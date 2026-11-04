import { VideoIcon } from "lucide-react";

function CallButton({ handleVideoCall }) {
  return (
    <button
      onClick={handleVideoCall}
      className="btn btn-success btn-sm btn-circle text-white absolute top-3 right-3 z-20 shadow-lg"
      title="Start video call"
    >
      <VideoIcon className="size-5" />
    </button>
  );
}

export default CallButton;
