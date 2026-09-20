import { Router, sendJson, readJson, token, nowIso } from './http.js';
import { hashPassword, verifyPassword, addMinutes } from './util.js';
import { getSetting } from './db.js';
import { removeUserThemes, themeCssForGateway } from './themes.js';
import { randomUUID } from 'node:crypto';

function sessionUser(user, mustChange = false) {
  return {
    id: user.id,
    role: user.role,
    username: user.username,
    nickname: user.nickname,
    uuid: user.uuid,
    level: user.level,
    authProvider: user.auth_provider || 'local',
    fnosUsername: user.fnos_username || null,
    mustChange,
  };
}

function gatewayLoginContext(req, cfg) {
  if (req.isFnosGateway !== true) {
    return { status: 403, error: '飞牛认证仅可通过统一网关访问' };
  }
  const fnosUserId = String(req.headers['x-trim-userid'] || '').trim();
  if (!fnosUserId) return { status: 401, error: '未收到飞牛账号信息' };
  const returnUrl = String(req.query.get('returnUrl') || '');
  let callback;
  try {
    callback = new URL(returnUrl);
  } catch {
    return { status: 400, error: '飞牛认证回调地址无效' };
  }
  if (!['http:', 'https:'].includes(callback.protocol) || Number(callback.port || 0) !== Number(cfg.port)) {
    return { status: 400, error: '飞牛认证回调地址不属于 WebDrop 服务端口' };
  }
  const forwardedHost = String(req.headers['x-forwarded-host'] || req.headers.host || '').split(',')[0].trim();
  try {
    if (forwardedHost && callback.hostname !== new URL(`http://${forwardedHost}`).hostname) {
      return { status: 400, error: '飞牛认证回调主机不匹配' };
    }
  } catch {
    return { status: 400, error: '飞牛认证主机无效' };
  }
  return {
    fnosUserId,
    fnosUsername: String(req.headers['x-trim-username'] || '').trim().slice(0, 100),
    callback,
  };
}

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[c]);
}

function issueToken(db, user, deviceId = '') {
  const value = token();
  db.prepare(
    'INSERT INTO tokens (token, user_id, device_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?)'
  ).run(value, user.id, String(deviceId || ''), nowIso(), addMinutes(30 * 24 * 60 * 60 * 1000));
  db.prepare('UPDATE users SET last_active_at = ? WHERE id = ?').run(nowIso(), user.id);
  return value;
}

export function authRoutes({ db, cfg, service, hub }) {
  const r = new Router();

  r.post('/api/auth/register', async (req, res) => {
    const b = await readJson(req);
    const username = String(b.username || '').trim();
    const password = String(b.password || '');
    const nickname = String(b.nickname || '').trim();
    const email = String(b.email || '').trim();
    const qq = String(b.qq || '').trim();
    if (!username || !password) {
      return sendJson(res, 400, { error: '用户名和密码不能为空' });
    }
    if (!email && !qq) {
      return sendJson(res, 400, { error: '邮箱或 QQ 号至少填写一种' });
    }
    const adminName = db.prepare("SELECT username FROM users WHERE role = 'admin' LIMIT 1").get()?.username;
    const conflict =
      db.prepare("SELECT 1 FROM users WHERE username = ? AND status != 'deleted'").get(username) ||
      db.prepare("SELECT 1 FROM registrations WHERE username = ? AND status = 'pending'").get(username);
    if (conflict || username === adminName) {
      return sendJson(res, 409, { error: '用户名已存在' });
    }
    const hash = await hashPassword(password);
    db.prepare(
      `INSERT INTO registrations (username, nickname, email, qq, password_hash, status, created_at)
       VALUES (?, ?, ?, ?, ?, 'pending', ?)`
    ).run(username, nickname, email || null, qq || null, hash, nowIso());
    sendJson(res, 201, { ok: true, pending: true, message: '注册申请已提交，等待管理员审核' });
  });

  r.post('/api/auth/login', async (req, res) => {
    const b = await readJson(req);
    const username = String(b.username || '').trim();
    const password = String(b.password || '');
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!user) {
      const reg = db
        .prepare('SELECT status FROM registrations WHERE username = ? ORDER BY id DESC LIMIT 1')
        .get(username);
      if (reg && reg.status === 'pending') {
        return sendJson(res, 403, { error: '账号待审核' });
      }
      return sendJson(res, 401, { error: '用户名或密码错误' });
    }
    if (!user.password_hash) {
      return sendJson(res, 401, { error: '用户名或密码错误' });
    }
    const ok = await verifyPassword(password, user.password_hash);
    if (!ok) return sendJson(res, 401, { error: '用户名或密码错误' });
    if (user.role !== 'admin') {
      if (user.status === 'pending') return sendJson(res, 403, { error: '账号待审核' });
      if (user.status === 'banned') return sendJson(res, 403, { error: '账号已被封禁' });
      if (user.status === 'deleted') return sendJson(res, 403, { error: '账号已删除' });
    }
    if (user.role === 'registered' && b.deviceId) {
      const dev = db
        .prepare('SELECT status FROM user_devices WHERE user_id = ? AND device_id = ?')
        .get(user.id, String(b.deviceId));
      if (dev && dev.status === 'blacklisted') {
        return sendJson(res, 403, { error: '该设备已被拉黑，无法登录' });
      }
    }
    const t = issueToken(db, user, b.deviceId);
    // 只有安全性最低的出厂凭据才需要强制修改。通过 fnOS 安装向导
    // 设置的自定义管理员凭据属于用户主动配置，不能被误判为首次登录。
    const usingDefault = user.role === 'admin' && username === 'admin' && password === 'admin';
    const mustChange = user.role === 'admin' && (user.must_change === 1 || usingDefault);
    if (mustChange) {
      db.prepare('UPDATE users SET must_change = 1 WHERE id = ?').run(user.id);
    }
    sendJson(res, 200, {
      token: t,
      user: sessionUser(user, mustChange),
    });
  });

  // 该路由只能由 index.js 的 Unix Socket 网关服务器标记后调用。
  // 绝不能信任公网端口上客户端伪造的 X-Trim-* Header。
  r.get('/api/auth/fnos/gateway-prompt', (req, res) => {
    const context = gatewayLoginContext(req, cfg);
    if (context.error) return sendJson(res, context.status, { error: context.error });
    const gatewayPrefix = req.fnosGatewayPrefix || '/app/WebDrop';
    const action = `${gatewayPrefix}/confirm?returnUrl=${encodeURIComponent(context.callback.toString())}`;
    const existingUser = db.prepare('SELECT uuid, theme FROM users WHERE fnos_user_id = ?').get(context.fnosUserId);
    const selectedTheme = existingUser?.theme || getSetting(db, 'globalTheme', 'default');
    // 主题 CSS 本来就由受信任的本地管理员或用户上传；避免意外闭合当前 style 标签。
    const themeCss = themeCssForGateway(cfg, selectedTheme, existingUser?.uuid).replace(/<\/style/gi, '<\\/style');
    const username = escapeHtml(context.fnosUsername || context.fnosUserId);
    const body = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>飞牛账号登录确认</title><style>${themeCss}</style><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg,#e0e5ec);color:var(--text,#4b5563);font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.box{width:min(420px,calc(100vw - 40px));box-sizing:border-box;padding:30px;background:var(--panel-bg,#fff);border:1px solid var(--border,#e4e7ec);border-radius:var(--radius-lg,20px);box-shadow:var(--shadow-md,0 12px 30px #10182818)}h1{font-size:21px;margin:0 0 14px;color:var(--text-strong,#1d2939)}p{line-height:1.6;color:var(--text,#475467)}.actions{display:flex;flex-direction:column;align-items:center;gap:13px;margin-top:24px}button{width:min(100%,300px);border:0;border-radius:var(--radius,14px);font-weight:700;cursor:pointer;transition:transform .15s ease,filter .15s ease}button:hover{transform:translateY(-1px);filter:brightness(.96)}button.confirm{padding:15px 20px;background:var(--accent,#6d5dfc);color:var(--on-accent,#fff);font-size:17px;box-shadow:var(--shadow-sm,0 4px 12px #0003);outline:2px solid var(--accent,#6d5dfc);outline-offset:2px}button.cancel{padding:11px 18px;background:var(--btn-secondary-bg,#eef2f6);color:var(--btn-secondary-text,#344054);font-size:15px;box-shadow:var(--shadow-sm,none)}</style></head><body><main class="box"><h1>飞牛账号登录确认</h1><p>当前飞牛账号：<strong>${username}</strong></p><p>确认后，WebDrop 将使用此飞牛账号登录。</p><form method="post" action="${escapeHtml(action)}"><div class="actions"><button type="submit" class="confirm">确认使用飞牛账号登录</button><button type="button" class="cancel" onclick="history.back()">取消</button></div></form></main></body></html>`;
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(body);
  });

  r.post('/api/auth/fnos/gateway', async (req, res) => {
    const context = gatewayLoginContext(req, cfg);
    if (context.error) return sendJson(res, context.status, { error: context.error });
    const { fnosUserId, fnosUsername, callback } = context;
    let user = db.prepare('SELECT * FROM users WHERE fnos_user_id = ?').get(fnosUserId);
    if (!user) {
      const ts = nowIso();
      const syntheticUsername = `fnos:${fnosUserId}`;
      const created = db.prepare(
        `INSERT INTO users (role, username, uuid, nickname, auth_provider, fnos_user_id, level, status, quota_bytes, used_bytes, created_at, last_active_at)
         VALUES ('registered', ?, ?, NULL, 'fnos', ?, 0, 'normal', 0, 0, ?, ?)`
      ).run(syntheticUsername, randomUUID(), fnosUserId, ts, ts);
      user = db.prepare('SELECT * FROM users WHERE id = ?').get(created.lastInsertRowid);
    }
    // 飞牛用户名以 UID 为身份主键。用户名发生变更时，下一次飞牛认证会同步这里的显示名。
    if (fnosUsername && user.fnos_username !== fnosUsername) {
      db.prepare('UPDATE users SET fnos_username = ? WHERE id = ?').run(fnosUsername, user.id);
      user = { ...user, fnos_username: fnosUsername };
    }
    db.prepare('DELETE FROM fnos_auth_codes WHERE expires_at <= ?').run(nowIso());
    const code = token();
    db.prepare(
      'INSERT INTO fnos_auth_codes (code, user_id, return_origin, expires_at, created_at) VALUES (?, ?, ?, ?, ?)'
    ).run(code, user.id, callback.origin, addMinutes(2 * 60 * 1000), nowIso());
    callback.searchParams.set('fnos_code', code);
    res.writeHead(302, { Location: callback.toString(), 'Cache-Control': 'no-store' });
    res.end();
  });

  r.post('/api/auth/fnos/complete', async (req, res) => {
    const b = await readJson(req);
    const code = String(b.code || '');
    const row = db.prepare('SELECT * FROM fnos_auth_codes WHERE code = ? AND expires_at > ?').get(code, nowIso());
    if (!row) return sendJson(res, 401, { error: '飞牛认证已失效，请重新认证' });
    const origin = String(req.headers.origin || '');
    if (origin && origin !== row.return_origin) return sendJson(res, 403, { error: '飞牛认证回调来源不匹配' });
    db.prepare('DELETE FROM fnos_auth_codes WHERE code = ?').run(code);
    const user = db.prepare('SELECT * FROM users WHERE id = ? AND auth_provider = ?').get(row.user_id, 'fnos');
    if (!user || user.status !== 'normal') return sendJson(res, 403, { error: '飞牛账号不可用' });
    const value = issueToken(db, user, b.deviceId);
    sendJson(res, 200, { token: value, user: sessionUser(user), needsNickname: !user.nickname });
  });

  r.post('/api/auth/logout', async (req, res) => {
    const auth = req.headers.authorization || '';
    if (auth.startsWith('Bearer ')) {
      const value = auth.slice(7);
      db.prepare('DELETE FROM tokens WHERE token = ?').run(value);
      // 已完成 WebSocket 鉴权的连接不会自动重新检查 Token，需要主动关闭当前 Token 的旧连接。
      hub.emitGlobal({ type: 'kickToken', token: value, reason: '已退出登录' });
    }
    sendJson(res, 200, { ok: true });
  });

  r.post('/api/auth/temp-logout', async (req, res) => {
    const tempId = req.headers['x-temp-id'];
    if (!tempId) return sendJson(res, 401, { error: '身份无效' });
    const user = db
      .prepare("SELECT * FROM users WHERE role = 'temp' AND uuid = ? AND status != 'deleted'")
      .get(tempId);
    if (!user) return sendJson(res, 404, { error: '账号不存在' });
    service.deleteUserFiles(user.id, 'user_deleted');
    db.prepare('UPDATE users SET username = NULL, used_bytes = 0, status = ? WHERE id = ?').run('deleted', user.id);
    removeUserThemes(cfg.dataDir, user.uuid);
    hub.emitGlobal({ type: 'kickUser', userId: user.id, reason: '已注销' });
    sendJson(res, 200, { ok: true });
  });

  r.post('/api/auth/change-password', async (req, res) => {
    const user = service.identify(req);
    if (!user) return sendJson(res, 401, { error: '未登录' });
    const b = await readJson(req);
    const newPassword = String(b.newPassword || '');
    const newUsername = String(b.newUsername || '').trim();
    if (user.role === 'admin') {
      if (user.must_change === 1) {
        if (!newUsername || !newPassword) {
          return sendJson(res, 400, { error: '管理员首次登录必须修改用户名和密码' });
        }
      } else if (b.currentPassword) {
        const ok = await verifyPassword(b.currentPassword, user.password_hash);
        if (!ok) return sendJson(res, 401, { error: '当前密码错误' });
      } else {
        return sendJson(res, 400, { error: '缺少当前密码' });
      }
      if (newUsername) {
        const conflict = db
          .prepare('SELECT 1 FROM users WHERE username = ? AND id != ?')
          .get(newUsername, user.id);
        if (conflict) return sendJson(res, 409, { error: '用户名已存在' });
      }
      const hash = newPassword ? await hashPassword(newPassword) : user.password_hash;
      db.prepare(
        'UPDATE users SET username = ?, password_hash = ?, must_change = 0 WHERE id = ?'
      ).run(newUsername || user.username, hash, user.id);
      // 撤销其他会话
      db.prepare('DELETE FROM tokens WHERE user_id = ? AND token != ?').run(
        user.id,
        (req.headers.authorization || '').slice(7)
      );
      return sendJson(res, 200, { ok: true });
    }
    // 普通用户改密
    const ok = await verifyPassword(String(b.currentPassword || ''), user.password_hash);
    if (!ok) return sendJson(res, 401, { error: '当前密码错误' });
    if (!newPassword) return sendJson(res, 400, { error: '新密码不能为空' });
    const hash = await hashPassword(newPassword);
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, user.id);
    sendJson(res, 200, { ok: true });
  });

  r.post('/api/auth/update-profile', async (req, res) => {
    const user = service.identify(req);
    if (!user || user.role !== 'registered') return sendJson(res, 401, { error: '需要登录' });
    const b = await readJson(req);
    if (user.auth_provider === 'fnos') {
      // 飞牛用户没有 WebDrop 密码；允许清空昵称，以便回退展示飞牛系统用户名。
      const nickname = String(b.nickname || '').trim().slice(0, 30);
      db.prepare('UPDATE users SET nickname = ? WHERE id = ?').run(nickname || null, user.id);
      return sendJson(res, 200, {
        ok: true,
        user: { ...sessionUser(user), nickname: nickname || null },
      });
    }
    const ok = await verifyPassword(String(b.currentPassword || ''), user.password_hash);
    if (!ok) return sendJson(res, 401, { error: '当前密码错误' });
    const nickname =
      b.nickname !== undefined ? String(b.nickname || '').trim().slice(0, 30) : user.nickname;
    let username = user.username;
    if (b.username !== undefined) {
      username = String(b.username || '').trim();
      if (!username) return sendJson(res, 400, { error: '用户名不能为空' });
      const conflict = db
        .prepare("SELECT 1 FROM users WHERE username = ? AND id != ? AND status != 'deleted'")
        .get(username, user.id);
      if (conflict) return sendJson(res, 409, { error: '用户名已存在' });
    }
    let passwordHash = user.password_hash;
    if (b.newPassword) {
      passwordHash = await hashPassword(String(b.newPassword));
    }
    db.prepare('UPDATE users SET username = ?, nickname = ?, password_hash = ? WHERE id = ?').run(
      username,
      nickname || null,
      passwordHash,
      user.id
    );
    sendJson(res, 200, {
      ok: true,
      user: { id: user.id, role: user.role, username, nickname, uuid: user.uuid },
    });
  });

  r.get('/api/auth/devices', async (req, res) => {
    const user = service.identify(req);
    if (!user) return sendJson(res, 401, { error: '未登录' });
    const rows = db
      .prepare('SELECT * FROM user_devices WHERE user_id = ? ORDER BY last_seen_at DESC')
      .all(user.id);
    sendJson(res, 200, {
      devices: rows.map((d) => ({
        deviceId: d.device_id,
        name: d.device_name,
        browser: d.browser,
        model: d.model,
        lastSeenAt: d.last_seen_at,
        status: d.status,
        createdAt: d.created_at,
      })),
    });
  });

  r.post('/api/auth/devices/:deviceId/logout', async (req, res) => {
    const user = service.identify(req);
    if (!user) return sendJson(res, 401, { error: '未登录' });
    const deviceId = req.params.deviceId;
    db.prepare('DELETE FROM tokens WHERE user_id = ? AND device_id = ?').run(user.id, deviceId);
    // 下线后设备记录消失，除非该设备再次主动上线
    db.prepare('DELETE FROM user_devices WHERE user_id = ? AND device_id = ?').run(user.id, deviceId);
    hub.emitGlobal({ type: 'kickDevice', userId: user.id, deviceId, reason: '设备已下线' });
    sendJson(res, 200, { ok: true });
  });

  r.post('/api/auth/devices/:deviceId/blacklist', async (req, res) => {
    const user = service.identify(req);
    if (!user) return sendJson(res, 401, { error: '未登录' });
    const deviceId = req.params.deviceId;
    db.prepare(
      `INSERT INTO user_devices (user_id, device_id, device_name, browser, model, last_seen_at, status, created_at)
       VALUES (?, ?, '', '', '', ?, 'blacklisted', ?)
       ON CONFLICT(user_id, device_id) DO UPDATE SET status = 'blacklisted'`
    ).run(user.id, deviceId, nowIso(), nowIso());
    db.prepare('DELETE FROM tokens WHERE user_id = ? AND device_id = ?').run(user.id, deviceId);
    hub.emitGlobal({ type: 'kickDevice', userId: user.id, deviceId, reason: '设备已被拉黑' });
    sendJson(res, 200, { ok: true });
  });

  r.post('/api/auth/devices/:deviceId/unblacklist', async (req, res) => {
    const user = service.identify(req);
    if (!user) return sendJson(res, 401, { error: '未登录' });
    db.prepare(
      "UPDATE user_devices SET status = 'normal' WHERE user_id = ? AND device_id = ?"
    ).run(user.id, req.params.deviceId);
    sendJson(res, 200, { ok: true });
  });

  r.get('/api/auth/me', async (req, res) => {
    const user = service.identify(req);
    if (!user) return sendJson(res, 401, { error: '未登录' });
    sendJson(res, 200, {
      user: {
        id: user.id,
        role: user.role,
        username: user.username,
        nickname: user.nickname,
        uuid: user.uuid,
        level: user.level,
        status: user.status,
        usedBytes: user.used_bytes,
        quotaBytes: service.quotaFor(user),
        mustChange: user.must_change === 1,
        theme: user.theme || null,
        authProvider: user.auth_provider || 'local',
        fnosUsername: user.fnos_username || null,
      },
    });
  });

  return r;
}
