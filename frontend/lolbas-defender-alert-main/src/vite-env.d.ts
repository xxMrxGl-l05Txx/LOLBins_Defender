/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Backend origin for API calls; leave unset to use the dev-server proxy */
  readonly VITE_API_URL?: string;
  /** Sent as X-API-Key when API authentication is enabled on the backend */
  readonly VITE_API_KEY?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
