export const OPEN_COMMAND_PALETTE_EVENT = "lolbins:open-command-palette";

export const openCommandPalette = () => {
  window.dispatchEvent(new Event(OPEN_COMMAND_PALETTE_EVENT));
};

export const isMacPlatform = () =>
  typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform);
