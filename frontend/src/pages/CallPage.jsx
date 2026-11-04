import { useEffect, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router";
import useAuthUser from "../hooks/useAuthUser";
import { useQuery } from "@tanstack/react-query";
import { getStreamToken } from "../lib/api";
import { StreamChat } from "stream-chat";

import {
  StreamVideo,
  StreamVideoClient,
  StreamCall,
  CallControls,
  SpeakerLayout,
  StreamTheme,
  CallingState,
  useCallStateHooks,
} from "@stream-io/video-react-sdk";

import "@stream-io/video-react-sdk/dist/css/styles.css";
import toast from "react-hot-toast";
import PageLoader from "../components/PageLoader";
import { CopyIcon, VideoIcon } from "lucide-react";
import { getMediaCallKey, recoverCallKeyFromHistory } from "../lib/crypto/chatCrypto";
import {
  installMediaSecurity,
  setActiveCallId,
  attachCallKeyToWorker,
} from "../lib/crypto/media";
import { isIdentityUnlocked } from "../lib/crypto/vault";

const STREAM_API_KEY = import.meta.env.VITE_STREAM_API_KEY;

// Frame-level E2EE hooks into every WebRTC peer connection created by the
// video SDK (idempotent; degrade to DTLS-SRTP where unsupported).
installMediaSecurity();

/**
 * Make sure this device holds the per-call session key:
 *   1. Same-tab navigation / reload → already in the local (sessionStorage) key registry.
 *   2. Fresh tab / other device while the identity vault is unlocked → re-open the
 *      media-key envelope waiting inside the SM-1 E2EE channel history.
 * Returns true when a key was secured (frame-level E2EE ON), false → degrade path.
 */
const secureCallKey = async (authUser, streamToken, callId) => {
  setActiveCallId(callId);
  if (getMediaCallKey(callId)) return true;

  try {
    // The vault must be unlocked to decrypt the recovery envelopes in history —
    // locked tabs simply ride on WebRTC's DTLS-SRTP (never fail-open).
    if (!isIdentityUnlocked()) return false;
    const chatClient = StreamChat.getInstance(STREAM_API_KEY);
    if (chatClient.user?.id !== authUser._id) {
      if (chatClient.user) await chatClient.disconnectUser();
      await chatClient.connectUser(
        {
          id: authUser._id,
          name: authUser.fullName,
          image: authUser.profilePic,
        },
        streamToken
      );
    }

    const recent = await chatClient.queryChannels(
      { type: "messaging", members: { $in: [authUser._id] } },
      {},
      { limit: 10, message_limit: 30 }
    );
    for (const channel of recent) {
      // eslint-disable-next-line no-await-in-loop
      if (await recoverCallKeyFromHistory(channel, callId)) return true;
    }
  } catch (error) {
    console.warn("[media-e2ee] Call-key recovery skipped:", error?.message ?? error);
  }
  return false;
};

const CallPage = () => {
  const { id: callId } = useParams();
  const [client, setClient] = useState(null);
  const [call, setCall] = useState(null);
  const [isConnecting, setIsConnecting] = useState(true);
  const [failed, setFailed] = useState(false);
  const callRef = useRef(null);
  const clientRef = useRef(null);

  const { authUser, isLoading } = useAuthUser();

  const { data: tokenData } = useQuery({
    queryKey: ["streamToken"],
    queryFn: getStreamToken,
    enabled: !!authUser,
    staleTime: Infinity,
  });

  useEffect(() => {
    if (!tokenData?.token || !authUser || !callId) return;

    let cancelled = false;

    const initCall = async () => {
      try {
        const videoClient = new StreamVideoClient({
          apiKey: STREAM_API_KEY,
          user: {
            id: authUser._id,
            name: authUser.fullName,
            image: authUser.profilePic,
          },
          token: tokenData.token,
        });
        clientRef.current = videoClient;

        // Secure the session key BEFORE any peer connection exists, so every
        // sender/receiver gets its sealing/unsealing transform immediately.
        let keyReady = await secureCallKey(authUser, tokenData.token, callId);
        if (cancelled) return;
        if (keyReady) {
          await attachCallKeyToWorker(callId).catch(() => {});
        } else {
          // Never invent a key here — a wrong key would brick the frame layer.
          // Without a key we simply keep WebRTC's mandatory DTLS-SRTP.
          console.info(
            "[media-e2ee] No per-call key for this session — using DTLS-SRTP transport protection."
          );
        }
        if (cancelled) {
          videoClient.disconnectUser().catch(() => {});
          return;
        }

        const callInstance = videoClient.call("default", callId);
        await callInstance.join({ create: true });

        if (cancelled) {
          callInstance.leave().catch(() => {});
          videoClient.disconnectUser().catch(() => {});
          return;
        }

        callRef.current = callInstance;
        setClient(videoClient);
        setCall(callInstance);
      } catch (error) {
        console.error("Error joining call:", error);
        if (!cancelled) {
          setFailed(true);
          toast.error("Could not join the call. Please try again.");
        }
      } finally {
        if (!cancelled) setIsConnecting(false);
      }
    };

    initCall();

    return () => {
      cancelled = true;
      const currentCall = callRef.current;
      const currentClient = clientRef.current;
      callRef.current = null;
      clientRef.current = null;
      if (currentCall) currentCall.leave().catch(() => {});
      if (currentClient) currentClient.disconnectUser().catch(() => {});
    };
  }, [tokenData?.token, authUser, callId]);

  if (isLoading || isConnecting) return <PageLoader />;

  if (failed || !client || !call) {
    return (
      <div className="h-full flex flex-col items-center justify-center gap-3 p-6 text-center">
        <VideoIcon className="size-12 opacity-30" />
        <p className="text-lg font-semibold">Could not initialize the call</p>
        <p className="text-sm opacity-60">Please refresh the page or try again later.</p>
      </div>
    );
  }

  return (
    <div className="h-full call-room">
      <StreamVideo client={client}>
        <StreamCall call={call}>
          <CallContent callId={callId} />
        </StreamCall>
      </StreamVideo>
    </div>
  );
};

const CallContent = ({ callId }) => {
  const { useCallCallingState } = useCallStateHooks();
  const callingState = useCallCallingState();
  const navigate = useNavigate();

  useEffect(() => {
    if (callingState === CallingState.LEFT) navigate("/");
  }, [callingState, navigate]);

  const copyLink = async () => {
    try {
      await navigator.clipboard.writeText(window.location.href);
      toast.success("Call link copied");
    } catch {
      toast.error("Could not copy the link");
    }
  };

  return (
    <StreamTheme className="call-theme">
      <div className="h-full flex flex-col relative">
        <div className="absolute top-0 inset-x-0 z-10 flex items-center justify-between gap-2 p-4 pointer-events-none">
          <div className="flex items-center gap-2 text-white/90 pointer-events-auto">
            <VideoIcon className="size-5" />
            <span className="font-semibold">Video call</span>
          </div>
          <button
            onClick={copyLink}
            className="btn btn-sm gap-1 bg-white/10 text-white border border-white/20 hover:bg-white/20 pointer-events-auto"
          >
            <CopyIcon className="size-4" />
            Copy link
          </button>
        </div>
        <div className="flex-1 min-h-0 pt-16">
          <SpeakerLayout />
        </div>
        <div className="shrink-0 call-controls-wrap">
          <CallControls />
        </div>
        <p className="sr-only">{callId}</p>
      </div>
    </StreamTheme>
  );
};

export default CallPage;
