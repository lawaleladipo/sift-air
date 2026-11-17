/**
 * Stateless SIFT-AIR API & Static Workbench Server (server/index.ts)
 * Zero database, zero disk persistence of case evidence.
 */

import http from "node:http";
import { runDacPreFlightLinter, type RuleSurface } from "../shared/dacPreFlightLinter.ts";
import { runDeterministicInvestigationPipeline } from "./geminiBroker.ts";

const PORT = Number(process.env.PORT ?? 8080);

function sendJson(res: http.ServerResponse, status: number, payload: unknown): void {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(payload, null, 2));
}

export function createSiftAirServer(): http.Server {
  return http.createServer((req, res) => {
    const url = req.url ?? "/";

    if (req.method === "GET" && url === "/api/health") {
      sendJson(res, 200, {
        service: "sift-air",
        version: "1.0.0",
        zeroRetention: true,
        diskPersistence: false,
      });
      return;
    }

    if (req.method === "POST" && (url === "/api/investigate" || url === "/api/lint")) {
      let body = "";
      req.on("data", (chunk) => {
        body += chunk;
        if (body.length > 2_000_000) req.destroy();
      });
      req.on("end", () => {
        try {
          const parsed = JSON.parse(body || "{}");
          if (url === "/api/lint") {
            const surface = (parsed.surface ?? "secops_yaral") as RuleSurface;
            const report = runDacPreFlightLinter(surface, String(parsed.content ?? ""), {
              lifecycleMode: parsed.lifecycleMode,
              ruleId: parsed.ruleId,
            });
            sendJson(res, 200, report);
            return;
          }
          const result = runDeterministicInvestigationPipeline(String(parsed.sanitizedTelemetry ?? ""));
          sendJson(res, 200, result);
        } catch (err) {
          sendJson(res, 400, {
            error: err instanceof Error ? err.message : "Invalid request payload",
          });
        }
      });
      return;
    }

    sendJson(res, 404, { error: "Route not found" });
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const srv = createSiftAirServer();
  srv.listen(PORT, "127.0.0.1", () => {
    process.stdout.write(`SIFT-AIR zero-retention broker listening on http://127.0.0.1:${PORT}\n`);
  });
}
