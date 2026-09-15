import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";

const SUMMARY_POLL_MS = 10000;

/** Dashboard counts, risk score, 7-day timeline and threat distribution */
export const useDashboardSummary = () =>
  useQuery({
    queryKey: ["summary"],
    queryFn: () => api.getSummary(7),
    refetchInterval: SUMMARY_POLL_MS,
    retry: false,
  });
