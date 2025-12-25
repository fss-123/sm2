#ifndef SM3_H
#define SM3_H

#include <stdint.h>
#include <stddef.h>

/*
 * SM3 上下文结构体 (Context)
 * 用于保存哈希计算过程中的中间状态
 */
typedef struct {
    uint32_t digest[8];    // 存放当前的哈希值 (也就是 IV 或者中间结果)
    uint64_t total_bytes;  // 已经处理的总字节数 (用于最后填充长度)
    uint8_t  buffer[64];   // 内部缓冲区 (攒够64字节才会进行一次压缩)
    size_t   buffer_len;   // 缓冲区当前已填充的字节数
} sm3_context;

/*
 * API 函数声明
 */

// 1. 初始化：重置上下文，加载 IV
void sm3_init(sm3_context *ctx);

// 2. 更新：输入数据 (可以多次调用)
// 比如先 update("a")，再 update("bc")，等同于 "abc"
void sm3_update(sm3_context *ctx, const uint8_t *input, size_t ilen);

// 3. 结束：处理填充，输出最终 32 字节哈希值
void sm3_final(sm3_context *ctx, uint8_t output[32]);

#endif // SM3_H