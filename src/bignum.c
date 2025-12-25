#include "bignum.h"
#include <stdio.h>
#include <string.h>

/* ==========================================================
 * 基础工具函数
 * ========================================================== */

/* 辅助：将单个 Hex 字符转为数字 */
static uint32_t hex_char_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

/* 读取 Hex 字符串到大数结构体 */
void bn_read_string(bignum256 *n, const char *hex) {
    memset(n, 0, sizeof(bignum256));
    int len = strlen(hex);
    int word_idx = 0;
    int shift = 0;

    // 倒序解析：从字符串末尾(低位)开始，填入 words[0](低位)
    for (int i = len - 1; i >= 0; i--) {
        uint32_t val = hex_char_to_int(hex[i]);
        if (word_idx < 8) {
            n->words[word_idx] |= (val << shift);
            shift += 4;
            if (shift >= 32) { // 填满一个 uint32，换下一个
                shift = 0;
                word_idx++;
            }
        }
    }
}

/* 打印大数 (从高位 words[7] 打印到低位 words[0]) */
void bn_print(const char *label, const bignum256 *n) {
    printf("%s: ", label);
    for (int i = 7; i >= 0; i--) {
        printf("%08x", n->words[i]);
    }
    printf("\n");
}

/* 比较大小: 1(a>b), -1(a<b), 0(a==b) */
int bn_cmp(const bignum256 *a, const bignum256 *b) {
    for (int i = 7; i >= 0; i--) {
        if (a->words[i] > b->words[i]) return 1;
        if (a->words[i] < b->words[i]) return -1;
    }
    return 0;
}

/* ==========================================================
 * 核心数学运算 (加减乘)
 * ========================================================== */

/* * [加法] r = a + b 
 * 返回值: carry (进位)
 * 原理: 模拟列竖式，低位先加，溢出的部分(>>32)放到下一位
 */
uint32_t bn_add(bignum256 *r, const bignum256 *a, const bignum256 *b) {
    uint64_t sum = 0;
    uint32_t carry = 0;
    for (int i = 0; i < 8; i++) {
        sum = (uint64_t)a->words[i] + b->words[i] + carry;
        r->words[i] = (uint32_t)sum;   // 取低32位
        carry = (uint32_t)(sum >> 32); // 取高32位作为进位
    }
    return carry;
}

/* * [减法] r = a - b 
 * 返回值: borrow (借位)
 * 原理: 计算机补码特性。
 * 如果 a < b，a - b 会变成一个巨大的正数(发生下溢)，且高位为1。
 */
uint32_t bn_sub(bignum256 *r, const bignum256 *a, const bignum256 *b) {
    uint64_t diff = 0;
    uint32_t borrow = 0;
    for (int i = 0; i < 8; i++) {
        // 使用 64 位临时变量防止溢出
        // diff = a[i] - b[i] - 上一轮借位
        diff = (uint64_t)a->words[i] - b->words[i] - borrow;
        
        r->words[i] = (uint32_t)diff;
        
        // 检查借位: 如果 diff 的第 63 位是 1，说明结果是负数，发生了借位
        borrow = (diff >> 63) & 1; 
    }
    return borrow;
}

/* * [乘法] r = a * b 
 * 原理: 两层循环 (Schoolbook Multiplication)。
 * 这是一个 O(N^2) 的算法，虽然不是最快，但是最简单且不易出错。
 */
void bn_mul(bignum512 *r, const bignum256 *a, const bignum256 *b) {
    memset(r, 0, sizeof(bignum512));

    for (int i = 0; i < 8; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < 8; j++) {
            // 核心公式: prod = a[i]*b[j] + 原有的r[i+j] + 进位
            uint64_t prod = (uint64_t)a->words[i] * b->words[j];
            prod += r->words[i + j]; // 累加到当前位
            prod += carry;           // 加上上一轮的进位
            
            r->words[i + j] = (uint32_t)prod; // 更新当前位
            carry = prod >> 32;               // 计算新的进位
        }
        // --- [修复重点 Start] ---
        // 处理外层进位传播：如果加 carry 后溢出，必须继续往高位进位
        int k = i + 8;
        while (carry > 0 && k < 16) {
            uint64_t sum = (uint64_t)r->words[k] + carry;
            r->words[k] = (uint32_t)sum;
            carry = sum >> 32; // 只有当 sum > 0xFFFFFFFF 时，carry 才会是 1，继续循环
            k++;
        }
        // --- [修复重点 End] ---
    }
}

/* ==========================================================
 * 模运算 (最容易出错的部分)
 * ========================================================== */

/* 辅助：获取 512位大数中的第 bit_idx 位 (0或1) */
static uint32_t bn512_get_bit(const bignum512 *n, int bit_idx) {
    int word_idx = bit_idx / 32;
    int bit_offset = bit_idx % 32;
    if (word_idx >= 16) return 0;
    return (n->words[word_idx] >> bit_offset) & 1;
}

/* 辅助：256位大数左移1位 */
static void bn_lshift(bignum256 *n) {
    uint32_t carry = 0;
    for (int i = 0; i < 8; i++) {
        uint32_t next_carry = n->words[i] >> 31; // 保存最高位
        n->words[i] = (n->words[i] << 1) | carry;
        carry = next_carry;
    }
}

/* * [取模] r = a % p 
 * 算法: 按位长除法 (Bitwise Long Division)
 * 修复说明: 之前这里有 Bug，如果 r 左移时最高位溢出，必须强制减 p。
 */
void bn_mod(bignum256 *r, const bignum512 *a, const bignum256 *p) {
    memset(r, 0, sizeof(bignum256));

    // 从最高位 (511) 扫描到 0
    for (int i = 511; i >= 0; i--) {
        // 1. 记录 r 左移前，最高位是否为 1 (如果为1，左移后就会溢出 256 位)
        int carry = (r->words[7] >> 31) & 1;
        
        // 2. 左移 r
        bn_lshift(r);
        
        // 3. 把被除数 a 的当前位补到 r 的最低位
        if (bn512_get_bit(a, i)) {
            r->words[0] |= 1;
        }

        // 4. 减法逻辑
        // 如果 carry=1 (说明 r 已经 > 2^256 > p)，或者 r >= p
        // 都需要减去 p
        if (carry || bn_cmp(r, p) >= 0) {
            bn_sub(r, r, p);
        }
    }
}

/* [模幂] r = base ^ exp % mod */
void bn_mod_exp(bignum256 *r, const bignum256 *base, const bignum256 *exp, const bignum256 *mod) {
    bignum256 b = *base;
    bignum256 e = *exp;
    bignum512 tmp;
    
    // 初始化 r = 1
    memset(r, 0, sizeof(bignum256));
    r->words[0] = 1;

    // 从高位到低位扫描指数 exp
    for (int i = 255; i >= 0; i--) {
        // r = r * r % mod
        bn_mul(&tmp, r, r);
        bn_mod(r, &tmp, mod);

        // 如果当前位是 1，则 r = r * base % mod
        int word_idx = i / 32;
        int bit_idx = i % 32;
        if ((e.words[word_idx] >> bit_idx) & 1) {
            bn_mul(&tmp, r, &b);
            bn_mod(r, &tmp, mod);
        }
    }
}

/* [模逆] r = a^(-1) % p */
void bn_mod_inv(bignum256 *r, const bignum256 *a, const bignum256 *p) {
    // 利用费马小定理: a^(p-2) = a^(-1) (mod p)
    bignum256 p_minus_2;
    bignum256 two;
    memset(&two, 0, sizeof(bignum256));
    two.words[0] = 2;
    
    bn_sub(&p_minus_2, p, &two); // p - 2
    bn_mod_exp(r, a, &p_minus_2, p);
}