# SM2-C: 纯 C 语言国密 SM2 算法库 (Zero-Dependency)


这是一个**纯 C 语言手写实现**的国密 SM2 椭圆曲线公钥密码算法库。如果不依赖 OpenSSL 等任何第三方大型库，从最底层的 256 位大数运算开始构建，直至实现完整的数字签名、公钥加密和 X.509 证书生成。

本项目旨在深入理解国密算法的数学原理与底层实现细节。

## 🚀 功能特性 (Features)

* **核心数学层 (Core Math)**
    * 自研 256-bit 大数运算库 (BigNum)：支持加、减、乘、模逆、模幂等运算。
    * 椭圆曲线算术 (ECC)：支持 Jacobian 坐标系下的点加、倍点、点乘运算。
* **SM2 协议层 (Protocol)**
    * ✅ **数字签名 (Signature):** 符合 GM/T 0003.2 标准，支持 `Sign` 和 `Verify`。
    * ✅ **密钥交换 (Key Exchange):** 符合 GM/T 0003.3 标准，模拟密钥协商流程。
    * ✅ **公钥加密 (Encryption):** 符合 GM/T 0003.4 标准，支持 C1||C3||C2 格式加解密。
* **应用层 (Application)**
    * ✅ **X.509 证书生成:** 内置简易 ASN.1 DER 编码器，可生成标准的 SM2 自签名证书 (`.crt`/`.pem`)，支持 OpenSSL 解析。
    * ✅ **集成 SM3:** 内置 SM3 杂凑算法实现。

## 📂 项目结构 (Structure)

```text
.
├── include/
│   ├── bignum.h    # 大数运算接口
│   ├── ec.h        # 椭圆曲线运算接口
│   ├── sm2.h       # SM2 核心功能接口 (签名/加密/交换)
│   ├── sm2_cert.h  # X.509 证书生成接口
│   └── sm3.h       # SM3 哈希算法接口
├── src/
│   ├── bignum.c    # 大数运算实现
│   ├── ec.c        # 椭圆曲线实现
│   ├── sm2.c       # SM2 协议逻辑
│   ├── sm2_cert.c  # ASN.1 编码与证书生成
│   ├── sm3.c       # SM3 实现
│   └── main.c      # 测试入口与示例
├── Makefile        # 构建脚本
└── README.md       # 项目说明
