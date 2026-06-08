# cyfs-gateway 编译热点与优化建议

数据来源：`/root/work/pve-pack-system/output/20260607-144303`

范围：

- 只分析 cyfs-gateway。
- Windows 本轮失败，不纳入。
- 编译时间来自 devkit `--timings-dir` 生成的 Cargo timing HTML。
- Cargo timing 中单个 unit 的耗时可以用于定位热点；多个 unit 会并行执行，所以“聚合热度”不能直接相加成 CI wall time。
- 第二个 arch 不是完全冷编译，因为同一项目的 target-dir 复用了第一轮 host/proc-macro/build-script 的部分产物。

## Cargo 编译窗口

| platform | arch | cargo wall time |
| --- | --- | ---: |
| Linux | amd64 | 728.4s / 12m 08.4s |
| Linux | arm64 | 582.2s / 9m 42.2s |
| macOS | amd64 | 1066.2s / 17m 46.2s |
| macOS | arm64 | 691.5s / 11m 31.5s |

按平台合计：

| platform | cyfs-gateway Rust 编译合计 |
| --- | ---: |
| Linux | 1310.6s / 21m 50.6s |
| macOS | 1757.7s / 29m 17.7s |

## 聚合热点

四份 cyfs-gateway timing 报告聚合后的 top heat：

| crate/unit | 聚合热度 | 单次最大 | 说明 |
| --- | ---: | ---: | --- |
| `openssl-sys v0.9.116` | 1113.9s / 18m 33.9s | 355.0s / 5m 55.0s | vendored OpenSSL build-script |
| `boa_engine v0.21.1` | 615.0s / 10m 15.0s | 212.9s / 3m 32.9s | JS engine |
| `aws-lc-sys v0.41.0` | 553.2s / 9m 13.2s | 167.8s / 2m 47.8s | AWS-LC build-script |
| `cyfs-gateway-lib v0.6.0` | 393.6s / 6m 33.6s | 114.4s / 1m 54.4s | gateway core lib |
| `cyfs_gateway v0.6.0` | 285.3s / 4m 45.3s | 56.8s | app crate + bin |
| `arrow-cast v55.2.0` | 273.6s / 4m 33.6s | 111.1s / 1m 51.1s | Arrow codegen-heavy |
| `arrow-ord v55.2.0` | 238.4s / 3m 58.4s | 86.0s / 1m 26.0s | Arrow codegen-heavy |
| `libsqlite3-sys v0.30.1` | 228.2s / 3m 48.2s | 74.1s / 1m 14.1s | bundled SQLite build-script |
| `reqwest v0.12.28` | 211.7s / 3m 31.7s | 49.3s | HTTP client |
| `cyfs-process-chain v0.6.0` | 201.4s / 3m 21.4s | 66.3s / 1m 06.3s | process chain |
| `rhai v1.25.1` | 182.6s / 3m 02.6s | 72.2s / 1m 12.2s | scripting engine |
| `arrow-select v55.2.0` | 179.3s / 2m 59.3s | 70.5s / 1m 10.5s | Arrow codegen-heavy |
| `cyfs-socks v0.6.0` | 143.6s / 2m 23.6s | 41.2s | includes Boa/HTTP related deps |
| `rustls v0.23.40` | 141.5s / 2m 21.5s | 48.4s | TLS stack |
| `cyfs-sn v0.6.0` | 132.2s / 2m 12.2s | 37.9s | SN component |
| `arrow-arith v55.2.0` | 128.8s / 2m 08.8s | 46.2s | Arrow codegen-heavy |
| `sfo-js v0.1.8` | 112.4s / 1m 52.4s | 38.7s | JS integration |
| `boa_ast v0.21.1` | 107.6s / 1m 47.6s | 38.0s | Boa dependency |
| `name-client v0.6.0` | 105.8s / 1m 45.8s | 37.7s | BuckyOS base dependency |
| `console-subscriber v0.5.0` | 87.4s / 1m 27.4s | 26.7s | tracing/diagnostic dependency |

## 分平台 top hotspots

### Linux amd64

Cargo wall time：728.4s / 12m 08.4s

| unit | 编译时间 |
| --- | ---: |
| `openssl-sys build-script(run)` | 355.0s / 5m 55.0s |
| `aws-lc-sys build-script(run)` | 167.8s / 2m 47.8s |
| `boa_engine` | 124.2s / 2m 04.2s |
| `cyfs-gateway-lib` | 101.0s / 1m 41.0s |
| `libsqlite3-sys build-script(run)` | 74.1s / 1m 14.1s |
| `arrow-cast` | 54.2s |
| `arrow-ord` | 52.8s |
| `cyfs_gateway` | 42.8s |
| `rhai` | 38.2s |
| `cyfs-process-chain` | 36.0s |

### Linux arm64

Cargo wall time：582.2s / 9m 42.2s

| unit | 编译时间 |
| --- | ---: |
| `openssl-sys build-script(run)` | 257.3s / 4m 17.3s |
| `boa_engine` | 122.8s / 2m 02.8s |
| `aws-lc-sys build-script(run)` | 114.7s / 1m 54.7s |
| `cyfs-gateway-lib` | 81.8s / 1m 21.8s |
| `libsqlite3-sys build-script(run)` | 60.6s / 1m 00.6s |
| `arrow-cast` | 50.3s |
| `arrow-ord` | 43.3s |
| `cyfs-process-chain` | 41.3s |
| `cyfs_gateway` | 34.2s |
| `rhai` | 32.1s |

### macOS amd64

Cargo wall time：1066.2s / 17m 46.2s

| unit | 编译时间 |
| --- | ---: |
| `openssl-sys build-script(run)` | 279.4s / 4m 39.4s |
| `boa_engine` | 212.9s / 3m 32.9s |
| `aws-lc-sys build-script(run)` | 144.7s / 2m 24.7s |
| `cyfs-gateway-lib` | 114.4s / 1m 54.4s |
| `arrow-cast` | 111.1s / 1m 51.1s |
| `arrow-ord` | 86.0s / 1m 26.0s |
| `rhai` | 72.2s / 1m 12.2s |
| `arrow-select` | 70.5s / 1m 10.5s |
| `cyfs-process-chain` | 66.3s / 1m 06.3s |
| `cyfs_gateway` | 56.8s |

### macOS arm64

Cargo wall time：691.5s / 11m 31.5s

| unit | 编译时间 |
| --- | ---: |
| `openssl-sys build-script(run)` | 218.5s / 3m 38.5s |
| `boa_engine` | 155.2s / 2m 35.2s |
| `aws-lc-sys build-script(run)` | 119.8s / 1m 59.8s |
| `cyfs-gateway-lib` | 96.5s / 1m 36.5s |
| `arrow-cast` | 58.0s |
| `cyfs-process-chain` | 57.8s |
| `arrow-ord` | 56.3s |
| `arrow-select` | 46.4s |
| `cyfs_gateway` | 42.0s |
| `rhai` | 40.0s |

## test_server 影响

本轮 devkit 仍然编译：

```text
-p cyfs_gateway -p test_server
```

`test_server` 自身 bin unit 耗时：

| platform | arch | `test_server` bin 编译时间 |
| --- | --- | ---: |
| Linux | amd64 | 11.9s |
| Linux | arm64 | 14.8s |
| macOS | amd64 | 11.6s |
| macOS | arm64 | 7.8s |

结论：

- `test_server` 自身不是主要热点。
- 如果 `test_server` 不属于 release payload，仍建议从 app modules/package 配置里移除；这样可以降低发布构建范围和未来依赖扩散风险。
- 但单独移除它无法解决当前最大编译耗时，主要矛盾仍是 OpenSSL、Boa、AWS-LC、Arrow/Rhai/SQLite 等依赖面。

## 依赖根因

### 1. OpenSSL

workspace manifest：

```toml
openssl = { version = "0.10", features = ["vendored"] }
```

ACME 直接使用 OpenSSL：

- `components/cyfs-acme/src/acme_client.rs`
  - RSA account key 生成。
  - 私钥 PEM 解析/序列化。
  - ACME JWS `RS256` 签名。
  - CSR 生成。
- `components/cyfs-acme/src/cert_mgr.rs`
  - `openssl::x509::X509` 解析证书。

因此在不改 ACME 实现的情况下，gateway 当前必须保留 OpenSSL。

### 2. reqwest 同时启用 rustls 和 default TLS

当前 workspace manifest：

```toml
reqwest = { version = "0.12.28", features = ["json","rustls-tls-native-roots"] }
```

因为没有 `default-features = false`，reqwest 的默认 `default-tls` 仍然启用，会额外拉入：

- `native-tls`
- `hyper-tls`
- `tokio-native-tls`
- OpenSSL 相关依赖

另外 `components/cyfs-socks/Cargo.toml` 当前有：

```toml
reqwest = "*"
```

这会绕过 workspace 约束，并再次启用 reqwest 默认特性。

### 3. jsonwebtoken 使用 AWS-LC backend

当前 workspace manifest：

```toml
jsonwebtoken = { version = "10", features = ["aws_lc_rs"] }
```

`aws_lc_rs` 会拉入 `aws-lc-sys`。本轮 timing 中 `aws-lc-sys` 是第三大聚合热点。

`jsonwebtoken` 10.x 的 `aws_lc_rs` 和 `rust_crypto` 是二选一 backend。`rust_crypto` backend 会使用 `ed25519-dalek`、`hmac`、`p256`、`p384`、`rsa`、`sha2` 等纯 Rust crate。当前代码大量使用 EdDSA/JWK，因此需要验证：

- `EncodingKey::from_ed_pem`
- `EncodingKey::from_ed_der`
- `DecodingKey::from_jwk`
- `DecodingKey::from_ed_components`
- `Algorithm::EdDSA`

### 4. Boa / JS dependency

`boa_engine` 是第二大聚合热点，且在四个 arch 上都很稳定。相关热点还包括：

- `sfo-js`
- `boa_ast`
- `cyfs-socks`

如果 JS/socks 相关能力不是所有发布场景都需要，值得评估 feature gate 或拆包。

### 5. Arrow / SQLite / Rhai

Arrow 相关 crate 和 SQLite/Rhai 也比较稳定：

- `arrow-cast`
- `arrow-ord`
- `arrow-select`
- `arrow-arith`
- `libsqlite3-sys`
- `rhai`

这些不是 TLS backend 问题，但属于第二梯队优化对象。

## 推荐优化顺序

### 阶段 1：收敛 reqwest TLS backend

改动小，风险低，建议最先做。

workspace：

```toml
reqwest = { version = "0.12.28", default-features = false, features = ["json", "rustls-tls-native-roots"] }
```

`components/cyfs-socks/Cargo.toml`：

```toml
reqwest.workspace = true
```

预期效果：

- `native-tls`、`hyper-tls`、`tokio-native-tls` 应从依赖图消失。
- 由于 ACME 仍直接依赖 OpenSSL，`openssl-sys` 不会完全消失。
- 但可以避免 reqwest 把 native TLS backend 额外并入依赖图，减少 TLS backend 混用。

验证：

```bash
cargo tree -i native-tls
cargo tree -i hyper-tls
cargo tree -i tokio-native-tls
cargo tree -i openssl-sys
```

### 阶段 2：评估 jsonwebtoken 从 aws_lc_rs 切到 rust_crypto

候选配置：

```toml
jsonwebtoken = { version = "10", default-features = false, features = ["rust_crypto"] }
```

预期效果：

- 如果没有其他依赖继续启用 `aws-lc-rs`，`aws-lc-sys` 应从构建图消失。
- 本轮 cyfs-gateway 四份 timing 中，`aws-lc-sys` 聚合热度为 553.2s / 9m 13.2s。
- 实际 wall time 收益不能直接等于 9m13s，但 clean VM + 双 arch 下应该能看到分钟级改善。

风险：

- AWS-LC 通常比 RustCrypto runtime 更快，尤其 RSA/ECDSA verify。
- gateway 当前主要 JWT 路径看起来偏 EdDSA/JWK，但仍需要真实 token/key 兼容测试。

建议补测试：

- Ed25519 PEM private key -> sign -> JWK public key verify。
- Ed25519 DER/PKCS8 private key -> sign -> verify。
- `DecodingKey::from_ed_components` verify。
- 现有线上/测试 token fixture 回归。

验证：

```bash
cargo tree -i aws-lc-sys
```

### 阶段 3：ACME 去 OpenSSL或隔离 OpenSSL

这是最大热点，但不是纯 manifest 优化。

可选路径：

1. 如果发布包默认不需要 ACME：给 `cyfs-acme` 加 feature gate，发布构建默认关闭。
2. 如果 ACME 是 gateway 必需能力：迁移实现到纯 Rust crypto/x509：
   - account key/JWS：`rsa` 或 `p256` + `signature` + `sha2`。
   - CSR：优先评估 `rcgen`；不够再看 `x509-cert`/`spki`/`pkcs8`。
   - cert parsing：`x509-parser` 或 `x509-cert`。
3. 兼容策略：保留旧 RSA account PEM 读取能力，或明确升级时重新生成 ACME account。

预期效果：

- 这是彻底移除 `openssl-sys` 的必要步骤。
- 本轮 cyfs-gateway 四份 timing 中，`openssl-sys` 聚合热度为 1113.9s / 18m 33.9s，单次最大 355.0s / 5m 55.0s。

### 阶段 4：拆分或 feature gate Boa/JS 能力

观察：

- `boa_engine` 聚合热度 615.0s / 10m 15.0s。
- `sfo-js`、`boa_ast`、`cyfs-socks` 也在热点列表中。

建议：

- 确认 `cyfs-socks` / JS script 能力是否是所有 gateway 发布包必需。
- 如果不是，增加 feature gate 或拆成可选组件。
- 如果是必需，短期不建议大改，只保留为第二阶段后续优化项。

### 阶段 5：梳理 Arrow / SQLite / Rhai

观察：

- Arrow 多个 crate 的 codegen 成本较高。
- `libsqlite3-sys` 使用 bundled SQLite build-script。
- `rhai` 也是稳定热点。

建议：

- 检查 `sfo-sql` / SQL / Arrow 相关 feature 是否过宽。
- 如果发布包不需要完整 Arrow 能力，尝试收窄 feature。
- 如果 CI 环境允许系统 SQLite，可评估不使用 bundled SQLite；但这会影响可重复构建和跨平台一致性，优先级低于 TLS/JWT/ACME。

## 建议 PR 拆分

1. **Manifest-only TLS cleanup**
   - `reqwest default-features = false`
   - `cyfs-socks` 改用 workspace reqwest
   - 验证 `native-tls` 链路消失

2. **JWT backend experiment**
   - `jsonwebtoken aws_lc_rs` -> `rust_crypto`
   - 补 EdDSA/JWK 兼容测试
   - 验证 `aws-lc-sys` 消失

3. **ACME OpenSSL strategy**
   - 明确 ACME 是否可 optional
   - 如果不可 optional，设计纯 Rust ACME key/JWS/CSR/cert parsing 迁移方案

4. **Boa/JS optionalization**
   - 确认 `cyfs-socks`/JS 能力是否发布必需
   - 可选则 feature gate 或拆包

## 最小验证闭环

先做 Linux amd64 单 arch timing，对比：

```bash
cargo tree -i native-tls
cargo tree -i openssl-sys
cargo tree -i aws-lc-sys
```

再比较 cargo timing：

- `openssl-sys` 是否仍在，以及是否只来自 ACME。
- `aws-lc-sys` 是否消失。
- `boa_engine`、`arrow-*` 是否成为新的主导热点。
- cargo wall time 是否从 728.4s 有明显下降。
