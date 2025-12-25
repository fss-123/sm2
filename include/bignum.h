#ifndef BIGNUM_H
#define BIGNUM_H

#include <stdint.h>
#include <stddef.h>

/*
 * =============================================================
 * 知识点 1: 多精度存储结构
 * SM2 需要 256 bit，我们用 8 个 32 bit 的整数数组来表示。
 * 存储方式: 小端序 (Little-Endian)
 * words[0] 存最低位 (Least Significant Word)
 * words[7] 存最高位 (Most Significant Word)
 * =============================================================
 */
typedef struct {
    uint32_t words[8];
} bignum256;

/*
 * API 函数声明
 */

// 从 16 进制字符串初始化大数 (如 "FFFF...")
// 知识点: 字符串通常是大端序，我们需要转换成内部的小端序
void bn_read_string(bignum256 *n, const char *hex);

// 打印大数 (输出为 Hex 字符串格式)
void bn_print(const char *label, const bignum256 *n);

// 比较大小: 返回 1 (a>b), -1 (a<b), 0 (a==b)
int bn_cmp(const bignum256 *a, const bignum256 *b);

// 大数加法: r = a + b
// 返回值: 最后的进位 (Carry)，如果返回 1 说明结果超过了 256 位 (溢出)
uint32_t bn_add(bignum256 *r, const bignum256 *a, const bignum256 *b);

// 大数减法: r = a - b
// 返回值: 最后的借位 (Borrow)，如果返回 1 说明结果是负数 (下溢)
uint32_t bn_sub(bignum256 *r, const bignum256 *a, const bignum256 *b);


/* 512位大整数 (用于存放乘法结果) */
typedef struct {
    uint32_t words[16]; // 16 * 32 = 512 bits
} bignum512;

/* 乘法: r (512位) = a (256位) * b (256位) */
void bn_mul(bignum512 *r, const bignum256 *a, const bignum256 *b);

/* * 模运算: r (256位) = a (512位) % p (256位)
 * 这是 SM2 算法中最频繁调用的函数之一
 */
void bn_mod(bignum256 *r, const bignum512 *a, const bignum256 *p);


// 模逆: r = a^(-1) % p
void bn_mod_inv(bignum256 *r, const bignum256 *a, const bignum256 *p);

#endif // BIGNUM_H