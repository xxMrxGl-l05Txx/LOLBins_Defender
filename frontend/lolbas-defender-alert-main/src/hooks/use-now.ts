import { useEffect, useState } from "react";

/** Re-render periodically so relative times ("12s ago") stay current */
export const useNow = (intervalMs = 5000) => {
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(timer);
  }, [intervalMs]);

  return now;
};
