import { useEffect, useState } from "react";
import { generateAvatar } from "../lib/utils";

const AvatarImage = ({ src, alt, name, className = "" }) => {
  const [current, setCurrent] = useState(src);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    setCurrent(src);
    setFailed(false);
  }, [src]);

  const handleError = () => {
    if (!failed) {
      setCurrent(generateAvatar(alt || name || "U", alt || name || 1));
      setFailed(true);
    }
  };

  return (
    <img
      src={current}
      alt={alt || name || "avatar"}
      onError={handleError}
      loading="lazy"
      className={className}
    />
  );
};

export default AvatarImage;
