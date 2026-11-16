import type { NextFunction, Request, Response } from "express";

// Every answer: no sniffing, no referrer, never cached.
export function secure(_req: Request, res: Response, next: NextFunction) {
  res.set({ "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Cache-Control": "no-store" });
  next();
}

export function health(_req: Request, res: Response) {
  res.type("text/plain; charset=utf-8").send("ok\n");
}
