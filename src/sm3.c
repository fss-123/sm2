#include "sm3.h"
#include <string.h> // for memcpy, memset

/* ============================================================
 * 基础宏定义
 * ============================================================ */

// 循环左移 (Rotate Left)
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// 大端序读写
#define GET_U32_BE(n, b, i)                             \
    {                                                   \
        (n) = ((uint32_t)(b)[(i)] << 24) |              \
              ((uint32_t)(b)[(i) + 1] << 16) |          \
              ((uint32_t)(b)[(i) + 2] << 8) |           \
              ((uint32_t)(b)[(i) + 3]);                 \
    }

#define PUT_U32_BE(n, b, i)                             \
    {                                                   \
        (b)[(i)] = (uint8_t)((n) >> 24);                \
        (b)[(i) + 1] = (uint8_t)((n) >> 16);            \
        (b)[(i) + 2] = (uint8_t)((n) >> 8);             \
        (b)[(i) + 3] = (uint8_t)((n));                  \
    }

/* ============================================================
 * SM3 专用置换与布尔函数
 * ============================================================ */

// 置换函数 P0 (用于压缩函数中 E 的更新)
// 公式: P0(X) = X ^ (X <<< 9) ^ (X <<< 17)
#define P0(x) ((x) ^ ROTL((x), 9) ^ ROTL((x), 17))

// 置换函数 P1 (用于消息扩展)
// 公式: P1(X) = X ^ (X <<< 15) ^ (X <<< 23)
#define P1(x) ((x) ^ ROTL((x), 15) ^ ROTL((x), 23))

// 布尔函数 FF
// 0-15轮: X ^ Y ^ Z
#define FF0(x, y, z) ((x) ^ (y) ^ (z))
// 16-63轮: (X & Y) | (X & Z) | (Y & Z)  (Majority)
#define FF1(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))

// 布尔函数 GG
// 0-15轮: X ^ Y ^ Z
#define GG0(x, y, z) ((x) ^ (y) ^ (z))
// 16-63轮: (X & Y) | (~X & Z)
#define GG1(x, y, z) (((x) & (y)) | ((~(x)) & (z)))

/* ============================================================
 * SM3 初始化向量 (IV)
 * ============================================================ */
static const uint32_t SM3_IV[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

 /* ============================================================
 * 核心压缩函数
 * 参数: 
 * digest: 当前的哈希值 (8个字)，运算结果会更新回这里
 * input:  当前的 64字节 数据块
 * ============================================================ */
static void sm3_compress(uint32_t digest[8], const uint8_t input[64]) {
    // 1. 定义扩展字数组
    // W[68]: 消息字
    // W1[64]: 异或后的消息字 (对应标准文档里的 W')
    uint32_t W[68];
    uint32_t W1[64];

    // 状态寄存器
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t SS1, SS2, TT1, TT2;
    
    int j; // 循环变量

    // ------------------------------------------------------------
    // 消息扩展 (Message Expansion)
    // ------------------------------------------------------------

    // A. 填充 W[0] ~ W[15]
    // 直接把输入的 64 字节 (byte) 转换成 16 个大端序整数 (uint32)
    for (j = 0; j < 16; j++) {
        GET_U32_BE(W[j], input, j * 4);
    }

    // B. 推导 W[16] ~ W[67]
    // 依据公式: W[j] = P1(W[j-16] ^ W[j-9] ^ ROTL(W[j-3], 15)) ^ ROTL(W[j-13], 7) ^ W[j-6]
    for (j = 16; j < 68; j++) {
        uint32_t temp = W[j-16] ^ W[j-9] ^ ROTL(W[j-3], 15);
        W[j] = P1(temp) ^ ROTL(W[j-13], 7) ^ W[j-6];
    }

    // C. 生成 W1[0] ~ W1[63] (即 W')
    // 公式: W'[j] = W[j] ^ W[j+4]
    for (j = 0; j < 64; j++) {
        W1[j] = W[j] ^ W[j+4];
    }

    // ------------------------------------------------------------
    // --------------------------------------------------------
    // 步骤 2: 64轮迭代压缩 (Compression)
    // --------------------------------------------------------

    // 2.1 加载中间状态到寄存器
    A = digest[0]; B = digest[1]; C = digest[2]; D = digest[3];
    E = digest[4]; F = digest[5]; G = digest[6]; H = digest[7];

    // 2.2 迭代循环 (为了性能，拆分为两个循环)

    // === Round 0 ~ 15 ===
    // 常量 T = 0x79CC4519
    // 使用 FF0, GG0
    for (j = 0; j < 16; j++) {
        // 计算中间变量 SS1
        // 公式: ROTL(ROTL(A,12) + E + ROTL(T, j), 7)
        SS1 = ROTL((ROTL(A, 12) + E + ROTL(0x79CC4519, j)), 7);
        
        // 计算 SS2
        SS2 = SS1 ^ ROTL(A, 12);

        // 计算 TT1 (使用 FF0, GG0)
        TT1 = FF0(A, B, C) + D + SS2 + W1[j];
        
        // 计算 TT2 (使用 GG0)
        TT2 = GG0(E, F, G) + H + SS1 + W[j];
        
        // 更新寄存器 (滑动窗口)
        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);
    }

    // === Round 16 ~ 63 ===
    // 常量 T = 0x7A879D8A
    // 使用 FF1, GG1
    for (j = 16; j < 64; j++) {
        // 注意：T 的移位逻辑也是 ROTL(T, j)
        SS1 = ROTL((ROTL(A, 12) + E + ROTL(0x7A879D8A, j)), 7);
        SS2 = SS1 ^ ROTL(A, 12);

        // 使用 FF1
        TT1 = FF1(A, B, C) + D + SS2 + W1[j];
        
        // 使用 GG1
        TT2 = GG1(E, F, G) + H + SS1 + W[j];
        
        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);
    }

    // --------------------------------------------------------
    // 步骤 3: 更新中间哈希值 (Feedback)
    // --------------------------------------------------------
    // 这里的异或 (^) 是 SM3 的特征，将压缩结果叠加回原有状态
    digest[0] ^= A;
    digest[1] ^= B;
    digest[2] ^= C;
    digest[3] ^= D;
    digest[4] ^= E;
    digest[5] ^= F;
    digest[6] ^= G;
    digest[7] ^= H;
}


/* ============================================================
 * 3. 核心 API 实现
 * ============================================================ */
/*
 * sm3_init: 初始化上下文
 * 1. 把 buffer 清空
 * 2. 计数器归零
 * 3. 把 digest 设为标准的 IV
 */
void sm3_init(sm3_context *ctx) {
    if (ctx == NULL) return;

    // 计数器清零
    ctx->total_bytes = 0;
    ctx->buffer_len = 0;

    // 清空缓冲区
    memset(ctx->buffer, 0, 64);

    // 加载标准 IV 到 digest 数组
    // 这里的 memcpy 比手写循环更高效
    memcpy(ctx->digest, SM3_IV, sizeof(SM3_IV));
}

/* ... (上面是 Day 1~3 的代码，不要动) ... */

/* ============================================================
 * 数据输入 (Update)
 * ============================================================ */
void sm3_update(sm3_context *ctx, const uint8_t *input, size_t ilen) {
    if (ctx == NULL || input == NULL || ilen == 0) return;

    size_t fill;
    size_t left;

    // 1. 只是简单的逐字节拷贝吗？不，为了性能，我们尽量整块处理
    
    // 之前 buffer 里剩了多少数据
    left = ctx->buffer_len;
    
    // buffer 还能装多少数据
    fill = 64 - left;

    // 更新总字节数计数器 (用于最后填充长度)
    ctx->total_bytes += ilen;

    // 情况 A: 输入数据够多，能把 buffer 填满
    if (left && ilen >= fill) {
        // 先把 buffer 填满
        memcpy(ctx->buffer + left, input, fill);
        
        // 压！(消化这 64 字节)
        sm3_compress(ctx->digest, ctx->buffer);
        
        // 调整指针和剩余长度
        input += fill;
        ilen  -= fill;
        left = 0; // buffer 清空了
    }

    // 情况 B: 处理中间的完整 64 字节块
    // 如果 input 里还有很多个 64 字节，直接压缩，不用拷贝到 buffer
    // (这是性能优化的关键点之一，减少内存拷贝)
    while (ilen >= 64) {
        sm3_compress(ctx->digest, input);
        input += 64;
        ilen  -= 64;
    }

    // 情况 C: 剩下的“尾巴”数据 (不足 64 字节)
    // 存入 buffer，留给下一次 update 或 final 处理
    if (ilen > 0) {
        memcpy(ctx->buffer + left, input, ilen);
    }

    // 更新 buffer 当前的使用量
    ctx->buffer_len = left + ilen;
}

/* ============================================================
 * API 完整实现: 填充与输出 (Final)
 * ============================================================ */
void sm3_final(sm3_context *ctx, uint8_t output[32]) {
    if (ctx == NULL || output == NULL) return;

    // 1. 获取 buffer 里还没处理的数据长度
    size_t last = ctx->buffer_len;
    
    // 2. 填充规则 Step 1: 先补一个 bit '1' (即字节 0x80)
    ctx->buffer[last] = 0x80;
    last++;

    // 3. 填充规则 Step 2: 补 '0'
    // 我们需要补 0 直到 buffer 剩下 8 个字节用来填长度 (也就是填到索引 56)
    
    if (last > 56) {
        // 特殊情况：如果数据太长，挤占了长度存放的位置
        // 比如 buffer 已经有了 60 字节，没地放长度了。
        // 解决：先把当前这块补 0 补满，压缩掉，然后开一个新块
        memset(ctx->buffer + last, 0, 64 - last);
        sm3_compress(ctx->digest, ctx->buffer);
        last = 0; // 新块从头开始
    }

    // 普通情况：补 0 补到 56
    memset(ctx->buffer + last, 0, 56 - last);

    // 4. 填充规则 Step 3: 填长度 (64位，大端序)
    // 注意：SM3 要求填的是【比特长度】，所以 total_bytes 要乘以 8
    // 我们用位移操作把 uint64_t 拆成两个 uint32_t
    
    uint64_t total_bits = ctx->total_bytes * 8;
    
    // 高 32 位
    uint32_t high = (uint32_t)(total_bits >> 32);
    // 低 32 位
    uint32_t low  = (uint32_t)(total_bits);

    // 写入最后 8 字节
    PUT_U32_BE(high, ctx->buffer, 56);
    PUT_U32_BE(low,  ctx->buffer, 60);

    // 5. 最后一次压缩
    sm3_compress(ctx->digest, ctx->buffer);

    // 6. 输出结果
    // 把内部的 8 个 uint32_t (digest) 转换为 32 个 uint8_t (output)
    for (int i = 0; i < 8; i++) {
        PUT_U32_BE(ctx->digest[i], output, i * 4);
    }
    
    // 7.清理敏感数据
    memset(ctx, 0, sizeof(sm3_context));
}