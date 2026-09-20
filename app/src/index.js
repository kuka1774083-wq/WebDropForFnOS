import http from 'node:http';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { loadConfig } from './config.js';
import { openDb, bootstrapAdmin } from './db.js';
import { Service } from './service.js';
import { Hub, WsServer } from './ws.js';
import { Router, sendJson, serveStatic } from './http.js';
import { authRoutes } from './auth.js';
import { roomRoutes } from './rooms.js';
import { fileRoutes } from './files.js';
import { adminRoutes } from './admin.js';
import { startJobs } from './jobs.js';
import { themeRoutes, installBundledThemes } from './themes.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

async function main() {
  const cfg = loadConfig(ROOT);
  fs.mkdirSync(cfg.dataDir, { recursive: true });
  const db = openDb(cfg.dbPath, cfg);
  await bootstrapAdmin(db, cfg);
  const service = new Service(db, cfg);
  const hub = new Hub();
  installBundledThemes(cfg);

  const api = new Router();
  api.get('/api/health', (req, res) => sendJson(res, 200, { ok: true }));

  const ctx = { db, cfg, service, hub };
  for (const router of [
    authRoutes(ctx),
    roomRoutes(ctx),
    fileRoutes(ctx),
    adminRoutes(ctx),
    themeRoutes(ctx),
  ]) {
    for (const route of router.routes) api.add(route.method, route.pattern, route.handler);
  }

  const appHandler = (req, res) => {
    if (req.url.startsWith('/api/')) {
      api.match(req, res, ctx).then((matched) => {
        if (!matched) sendJson(res, 404, { error: 'Not Found' });
      });
      return;
    }
    const urlPath = (req.url || '/').split('?')[0];
    if (urlPath === '/admin' || urlPath === '/admin/') {
      // 独立管理面板页（仅管理员登录、可多开）
      serveStatic(res, path.join(ROOT, 'public'), '/admin.html');
      return;
    }
    serveStatic(res, path.join(ROOT, 'public'), req.url);
  };

  // 独立端口继续提供全部 WebDrop 功能与免登录访问。
  const server = http.createServer(appHandler);
  // 飞牛统一网关只用于账号认证。它监听 Unix Socket，不能由公网 TCP
  // 客户端连接，因此网关身份 Header 不会被伪造到独立端口。
  const gatewaySocket = process.env.WEBDROP_GATEWAY_SOCKET || '';
  const gatewayPrefix = process.env.WEBDROP_GATEWAY_PREFIX || '/app/WebDrop';
  let gatewayServer = null;
  if (gatewaySocket && process.platform !== 'win32') {
    try { fs.unlinkSync(gatewaySocket); } catch (e) { if (e.code !== 'ENOENT') throw e; }
    gatewayServer = http.createServer((req, res) => {
      const url = new URL(req.url || '/', 'http://localhost');
      const isLoginPage = req.method === 'GET' && (
        url.pathname === gatewayPrefix || url.pathname === `${gatewayPrefix}/fnos-login`
      );
      const isLoginConfirm = req.method === 'POST' && url.pathname === `${gatewayPrefix}/confirm`;
      if (!isLoginPage && !isLoginConfirm) {
        res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ error: 'Not Found' }));
        return;
      }
      // 仅此 Unix Socket 服务可设置该内部标记；认证路由以它作为
      // 接受 X-Trim-* Header 的前提。
      req.isFnosGateway = true;
      req.fnosGatewayPrefix = gatewayPrefix;
      req.url = `${isLoginConfirm ? '/api/auth/fnos/gateway' : '/api/auth/fnos/gateway-prompt'}${url.search}`;
      appHandler(req, res);
    });
    // 网关仅用于飞牛账号认证；Socket 不可用时仍保持独立端口可访问。
    gatewayServer.on('error', (error) => {
      console.error(`WebDrop 飞牛认证网关不可用: ${error.message}`);
    });
  }

  const wss = new WsServer({ httpServer: server, db, cfg, service, hub });
  wss.startHeartbeat();

  service.onFileReady = (file) => {
    if (file.scope !== 'room') return;
    const room = db.prepare('SELECT room_number FROM rooms WHERE id = ?').get(file.ref_id);
    if (room) hub.emitRoom(room.room_number, { type: 'roomFileReady', file: service.publicFile(file) });
  };

  startJobs({ db, cfg, service, hub });

  server.listen(cfg.port, cfg.host, () => {
    console.log(`WebDrop 已启动: http://${cfg.host}:${cfg.port}`);
  });
  if (gatewayServer) gatewayServer.listen(gatewaySocket, () => console.log(`WebDrop 飞牛认证网关已启动: ${gatewaySocket}`));

  const shutdown = () => {
    console.log('正在关闭...');
    server.close(() => {
      if (gatewayServer) gatewayServer.close(() => process.exit(0));
      else process.exit(0);
    });
    setTimeout(() => process.exit(0), 3000).unref();
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
