// One JSON object per line on stdout. Nothing secret is ever logged: tokens
// are referred to by their verification reason only.

export type Fields = Record<string, unknown>;

export interface Logger {
  info(msg: string, fields?: Fields): void;
  warn(msg: string, fields?: Fields): void;
  error(msg: string, fields?: Fields): void;
}

export function jsonLogger(write: (line: string) => void = (l) => process.stdout.write(l + "\n")): Logger {
  const at = (level: string) => (msg: string, fields: Fields = {}) =>
    write(JSON.stringify({ time: new Date().toISOString(), level, msg, ...fields }));
  return { info: at("INFO"), warn: at("WARN"), error: at("ERROR") };
}

export const silent: Logger = { info: () => {}, warn: () => {}, error: () => {} };
