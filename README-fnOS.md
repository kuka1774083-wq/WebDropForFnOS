# WebDrop for fnOS

这是 WebDrop 的飞牛 fnOS 原生应用包工程。它使用飞牛 Node.js v22 运行时直接启动 WebDrop，不安装或创建 Docker 容器；运行数据保存在应用自己的 `TRIM_PKGVAR/config` 与 `TRIM_PKGVAR/data` 目录中。

- 作者项目主页：https://github.com/kuka1774083-wq/WebDropForFnOS
- 发布者主页：https://space.bilibili.com/41158746?spm_id_from=333.1007.0.0

## 打包

在本目录安装 fnpack 后执行：

```powershell
fnpack build -d .
```

安装向导默认使用 8080 端口。修改端口后，请从 `http://飞牛主机IP:所选端口` 访问 WebDrop。

安装时可明文设置 WebDrop 管理员账号和密码，默认均为 `admin`。自定义凭据不会触发首次登录改密；仅默认 `admin/admin` 会要求修改。飞牛管理员桌面还会显示“WebDrop 管理后台”图标，直达 `/admin`。

WebDrop 的独立端口继续支持免登录访问。登录页的“使用飞牛账号登录”会先打开同一主机的飞牛原生登录页（HTTP 为 `5666` 端口、HTTPS 为 `5667` 端口）；登录成功后才回跳至统一网关入口 `/app/WebDrop`。网关校验飞牛会话后显示账号登录确认页，确认后才会回到独立端口。飞牛账号首次仅需填写昵称，设置页不显示用户名和密码修改选项；用户名前会显示 `[fnos]`，清空昵称后会回退显示飞牛系统用户名。

内置公共主题会随安装包提供。应用启动和升级时会将缺失的主题补回 `data/themes/public`，不会覆盖已有主题文件。

卸载向导默认保留使用记录。选择清除后，会删除数据库、上传文件、聊天记录和配置。
