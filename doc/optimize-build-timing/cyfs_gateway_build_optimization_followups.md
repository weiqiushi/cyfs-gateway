# cyfs-gateway 编译时间后续优化方案

本文记录需要进一步评估或会改变实现边界的编译时间优化项。已能直接落地的配置类优化放在提交中完成；本文只作为后续改动的实施方案和验证清单。

## 已直接落地的配置优化

1. 发布包使用轻量 app 配置：
   - `src/bucky_project.yaml` 新增 `cyfs-gateway-publish`，只打包 `cyfs_gateway`。
   - release workflow 改为 `buckyos-build --app=cyfs-gateway-publish`。
   - 目的：release 构建不再包含 `test_server` bin，降低发布构建范围和未来依赖扩散风险。

2. 本仓库内 `reqwest` 依赖收敛：
   - workspace `reqwest` 关闭默认特性，并显式使用 `json`、`rustls-tls-native-roots`。
   - `cyfs-socks` 改用 `reqwest.workspace = true`，避免 `reqwest = "*"` 重新启用默认特性。

## 当前依赖图发现

执行 `cargo tree -e features -i reqwest` 后发现，虽然本仓库内的 `reqwest` 已收敛，但 `native-tls` 链路仍未完全消失，主要来自：

- `sfo-js v0.1.8 -> boa_runtime v0.21.1 features = ["all"]`
- `boa_runtime/all -> reqwest-blocking -> reqwest/default`
- `ndn-lib` 默认 feature 也会启用 `reqwest/default`

因此，彻底移除 `native-tls` 不是单纯修改本仓库 workspace manifest 就能完成，需要处理 `sfo-js` / `boa_runtime` / `ndn-lib` 的 feature 边界。

## 验证记录

2026-06-08：

- 本地执行 `cargo metadata --locked --offline --no-deps` 通过，manifest 解析正常。
- 本地执行 `cargo tree -e features -i reqwest`，确认本仓库内 `reqwest` 已关闭默认特性，但 `native-tls` 仍由 `sfo-js -> boa_runtime/all` 和 `ndn-lib` 默认 feature 打开。
- 打包机执行 `buckyos-build --app=cyfs-gateway-publish` 时，devkit 已正确选择 `cyfs_gateway`，生成的 cargo 命令为 `cargo build --release --target x86_64-unknown-linux-musl --target-dir /tmp/rust_build/cyfs-gateway -p cyfs_gateway`，不再包含 `-p test_server`。
- 打包机完整构建未完成，原因是 crates.io 网络多次 `Timeout was reached` / HTTP2 stream error；离线重试因打包机 Cargo 缓存缺少 `quote` 失败。这不是本次 manifest 改动导致的编译错误。

## 方案 A：Boa / sfo-js fetch 能力收窄

目标：

- 去掉 `boa_runtime/all` 对 `reqwest/default` 的启用。
- 保留当前必需的 JS 执行、`console`、PAC 和 DNS provider 能力。

现状：

- 本仓库直接用到 `boa_runtime::Console`：
  - `components/cyfs-process-chain/src/js/exec.rs`
  - `components/cyfs-socks/src/rule/pac.rs`
- ACME DNS provider 脚本实际使用 `fetch`：
  - `rootfs/etc/cyfs_gateway/acme_dns_provider/aliyun/main.js`
- `sfo-js v0.1.8` 固定依赖 `boa_runtime` 的 `all` feature，当前无法仅通过本仓库 manifest 关闭。

候选路径：

1. 优先推动 `sfo-js` 增加 feature：
   - 默认只启用 JS engine / console 所需能力。
   - `fetch` 单独作为可选 feature。
   - 内部 `reqwest` 使用 `default-features = false`，并显式启用 rustls。
2. 本仓库跟进：
   - 普通 gateway JS 模板默认关闭 fetch。
   - ACME DNS provider 需要 fetch 时通过 `cyfs-acme` feature 显式开启。
3. 如果短期不能改上游：
   - 先记录为上游依赖问题，不在本仓库引入 patch fork。

验证：

```bash
cargo tree -e features -i reqwest
cargo tree -i native-tls
cargo tree -i hyper-tls
cargo tree -i tokio-native-tls
```

## 方案 B：NDN 默认 feature 收窄

目标：

- 避免 `ndn-lib` 默认 feature 重新启用 `reqwest/default`。

候选路径：

1. 检查 `cyfs-ndn` 中 `ndn-lib`、`ndm`、`named_store` 的 feature 定义。
2. 如果 NDN HTTP client 能力可选：
   - 本仓库依赖改为 `default-features = false`。
   - 只启用 gateway 运行实际需要的 feature。
3. 如果 NDN 需要 reqwest：
   - 上游将 reqwest 配置切到 `default-features = false` + rustls。

验证：

```bash
cargo tree -e features -p cyfs-gateway-lib -i reqwest
cargo tree -i native-tls
```

## 方案 C：JWT backend 从 AWS-LC 切到 RustCrypto

目标：

- 将 `jsonwebtoken` 从 `aws_lc_rs` backend 切到 `rust_crypto` backend，移除 `aws-lc-sys` build-script 热点。

候选配置：

```toml
jsonwebtoken = { version = "10", default-features = false, features = ["rust_crypto"] }
```

风险：

- 这是密码学后端实现替换，虽然调用代码不一定变，但验签/签名兼容性需要认真回归。
- AWS-LC runtime 性能通常优于 RustCrypto，尤其 RSA/ECDSA 路径。

必须补充或确认的测试：

1. Ed25519 PEM private key sign -> JWK public key verify。
2. Ed25519 DER/PKCS8 private key sign -> verify。
3. `DecodingKey::from_ed_components` verify。
4. 现有线上/测试 token fixture 回归。
5. 如果存在 RSA/ECDSA token，必须覆盖对应算法。

验证：

```bash
cargo test -p cyfs_gateway test_login -- --nocapture
cargo test -p cyfs-sn -- --test-threads=1
cargo tree -i aws-lc-sys
```

## 方案 D：ACME 去 OpenSSL 或隔离 OpenSSL

目标：

- 移除或隔离 `openssl-sys`，这是当前最大编译热点。

候选路径：

1. 如果发布包默认不需要 ACME：
   - 将 `cyfs-acme` 设为 optional feature。
   - 默认 release 关闭 ACME，提供带 ACME 的构建 profile/app。
2. 如果 ACME 必需：
   - JWS account key/sign：评估 `rsa`/`signature`/`sha2`。
   - CSR：优先评估 `rcgen`，必要时评估 `x509-cert`/`spki`/`pkcs8`。
   - cert parsing：评估 `x509-parser` 或 `x509-cert`。
3. 兼容策略：
   - 保留旧 RSA account PEM 读取能力，或明确升级时重新生成 ACME account。

必须验证：

1. 现有 account key 读取。
2. 新 account key 生成和 JWS 签名。
3. CSR 内容兼容 ACME server。
4. 证书链解析和过期时间读取。
5. DNS-01 provider 脚本流程。

验证：

```bash
cargo test -p cyfs-acme -- --test-threads=1
cargo tree -i openssl-sys
```

## 建议后续拆分

1. `sfo-js`/Boa feature 收窄实验。
2. `ndn-lib` feature 收窄实验。
3. `jsonwebtoken` RustCrypto 后端实验加测试。
4. ACME OpenSSL optionalization 或纯 Rust 迁移方案。
