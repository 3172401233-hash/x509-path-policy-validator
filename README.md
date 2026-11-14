# x509-path-policy-validator

离线 JavaScript X.509 证书路径构建与校验库。不访问网络、无第三方依赖，
仅使用 `node:crypto` 做签名运算，证书解析由内置的极简 DER 读取器完成。

设计动机：仅按 issuer/subject 名称（如 common name）匹配链路的实现会把
"同名但密钥错误"的签发者当成有效。本库对每一条候选路径做完整的密码学
签名校验与策略检查，名称只用于候选检索，绝不作为信任依据。

## 用法

```js
import { validateCertificatePath } from './src/index.js';

const result = validateCertificatePath({
  leaf: leafPem,                    // PEM 字符串或 Certificate 实例
  intermediates: [interPem],        // 候选中间证书（可含交叉签名副本）
  trustAnchors: [rootPem],          // 多个信任锚（须为自签 CA）
  hostname: 'www.example.com',      // 可选，主机名校验
  at: new Date(),                   // 可选，校验时间点
  revocation: [                     // 可选，离线吊销记录
    { issuer: 'CN=Inter A', serialNumber: '03e8' },
    { fingerprint256: 'ab12...' },
  ],
  maxPathLength: 8,                 // 可选，路径中 CA 证书数上限
});
// result.ok       — 是否选出有效路径
// result.selected — 选中的路径（subject + SHA-256 指纹序列）及锚
// result.rejected — 被淘汰的候选路径及淘汰原因（reason + detail）
```

路径构建从叶证书向信任锚做深度优先搜索：按 subject 检索候选签发者
（处理交叉签名与多个同名 subject），按证书指纹打破重复证书环，
`maxPathLength` 限制搜索深度。所有候选路径按
（锚指纹、路径长度、链上指纹序列）做稳定排序，因此多个信任锚下
选中的路径是确定性的；其余有效路径以 `valid-but-not-selected` 列出。

## 每条路径执行的检查

- 签名链：RSA（SHA-1/256/384/512）与 ECDSA（P-256/P-384/P-521，DER 编码）
- 有效期（notBefore / notAfter，可指定 `at`）
- BasicConstraints：CA 标志、pathLenConstraint
- KeyUsage：CA 必须含 keyCertSign（扩展存在时）
- ExtendedKeyUsage：叶证书与 CA 均须允许请求的用途（默认 serverAuth）；
  扩展缺失视为不限制，anyEKU 视为通配
- 名称约束：permitted/excluded 子树，支持 dNSName 与 directoryName 两种形式
- 主机名：SAN dNSName 匹配，支持单标签通配符 `*.example.com`；
  无 SAN 时回退到 subject CN
- 未知 critical 扩展：直接拒绝（fail-closed）
- 离线吊销记录：按 (issuer, serialNumber) 或 SHA-256 指纹匹配
- 信任锚：必须自签且自签名可验证

## 支持的扩展

| 扩展 | OID | 处理 |
| --- | --- | --- |
| BasicConstraints | 2.5.29.19 | 强制（CA 标志、pathLenConstraint） |
| KeyUsage | 2.5.29.15 | 强制（CA 的 keyCertSign） |
| ExtendedKeyUsage | 2.5.29.37 | 强制（叶与 CA） |
| SubjectAltName | 2.5.29.17 | dNSName 用于主机名与名称约束 |
| NameConstraints | 2.5.29.30 | dNSName、directoryName 子树 |
| SubjectKeyIdentifier | 2.5.29.14 | 解析，不参与决策 |
| AuthorityKeyIdentifier | 2.5.29.35 | 解析，不参与决策 |
| CertificatePolicies | 2.5.29.32 | 解析，不参与决策 |
| CRLDistributionPoints | 2.5.29.31 | 解析，不参与决策（离线模型） |

不在上表中的 critical 扩展一律导致证书被拒绝。

## 未实现项

- CRL / OCSP 协议获取与签名验证（仅接受调用方提供的离线吊销记录）
- 证书策略（policy mapping / inhibitPolicyMapping）与 inhibitAnyPolicy 处理
- 名称约束中的 rfc822Name、URI、iPAddress 等 GeneralName 形式
  （出现时按 fail-closed 拒绝）
- RSASSA-PSS、Ed25519/Ed448 签名算法（出现时按不支持拒绝）
- SAN 中的 iPAddress 主机名匹配、IDNA 国际化域名
- 信任锚仅支持自签 CA 形式，不支持"信任锚即叶证书"等裸公钥模型

## 测试

```
npm test          # node --test
```

测试证书预生成并提交在 `test/fixtures/`（含私钥，仅供测试）。
覆盖：正常链、同名 CN 伪造签发者、交叉签名双锚、断裂链、交叉签名环、
名称约束失败/通过、错误 EKU、过期、吊销（序列号与指纹两种形式）、
未知 critical 扩展、主机名不匹配、通配符、CN 回退、pathLenConstraint、
非自签锚、maxPathLength。重新生成夹具（需要 openssl >= 3.2）：

```
npm run generate-fixtures
```
