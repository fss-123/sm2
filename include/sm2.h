#ifndef SM2_H
#define SM2_H

#include "ec.h"
#include "sm3.h"

/* SM2 密钥对 */
typedef struct {
    bignum256 d;        // 私钥 (大整数)
    ec_point P;         // 公钥 (曲线上的点 P = d*G)
} sm2_key_pair;

/* SM2 签名结果 (r, s) */
typedef struct {
    bignum256 r;
    bignum256 s;
} sm2_signature;

/*
 * [API] 生成 SM2 密钥对
 * pri_hex: 私钥的 Hex 字符串 (测试时指定，生产环境应随机生成)
 */
void sm2_keygen(sm2_key_pair *key, const char *pri_hex);

/*
 * [API] SM2 签名
 * msg: 消息内容
 * msg_len: 消息长度
 * id: 用户ID (通常为 "1234567812345678")
 * id_len: ID长度
 * pub: 公钥 (用于计算 ZA)
 * pri: 私钥 (用于签名)
 * k_hex: 随机数 k (为了通过标准测试向量，我们允许外部传入固定的 k)
 * sig: 输出签名结果
 */
void sm2_sign(sm2_signature *sig,
              const uint8_t *msg, int msg_len,
              const uint8_t *id, int id_len,
              const ec_point *pub, const bignum256 *pri,
              const char *k_hex); // ⚠️ 测试用固定 k

/*
 * [API] SM2 验签
 * 返回值: 0 成功 (Valid), 1 失败 (Invalid)
 */
int sm2_verify(const sm2_signature *sig,
               const uint8_t *msg, int msg_len,
               const uint8_t *id, int id_len,
               const ec_point *pub);



/* * [API] SM2 密钥交换 - 计算共享密钥
 * 这是一个“单边”函数。Alice 调用它算一遍，Bob 调用它算一遍，结果应该一样。
 *
 * k_len:      期望生成的密钥长度 (如 16 字节用于 SM4)
 * k_out:      输出密钥缓冲区
 *
 * self_id, self_id_len: 自己的 ID
 * self_pub, self_pri:   自己的长期公钥、私钥
 * self_tmp_pub, self_tmp_pri: 自己的临时公钥、私钥 (随机生成的 r, R)
 *
 * other_id, other_id_len: 对方的 ID
 * other_pub:              对方的长期公钥
 * other_tmp_pub:          对方的临时公钥
 */
void sm2_exchange_key(uint8_t *k_out, int k_len,
                      const uint8_t *self_id, int self_id_len,
                      const ec_point *self_pub, const bignum256 *self_pri,
                      const ec_point *self_tmp_pub, const bignum256 *self_tmp_pri,
                      const uint8_t *other_id, int other_id_len,
                      const ec_point *other_pub, const ec_point *other_tmp_pub);


/* * SM2 加密
 * msg:      明文数据
 * msg_len:  明文长度
 * pub:      接收方的公钥
 * k_hex:    随机数 k (测试用固定值，生产环境应为 NULL 或随机)
 * out:      输出缓冲区 (密文 C1||C3||C2)
 * 长度 = 64(C1) + 32(C3) + msg_len(C2) = msg_len + 96
 * 返回值:   1 成功, 0 失败
 */
int sm2_encrypt(uint8_t *out, 
                const uint8_t *msg, int msg_len,
                const ec_point *pub, 
                const char *k_hex);

/* * SM2 解密
 * cipher:      密文数据 (C1||C3||C2 格式)
 * cipher_len:  密文总长度
 * pri:         接收方的私钥
 * plain:       输出缓冲区 (明文)
 * 长度 = cipher_len - 96
 * 返回值:      1 成功, 0 失败 (校验 C3 失败)
 */
int sm2_decrypt(uint8_t *plain,
                const uint8_t *cipher, int cipher_len,
                const bignum256 *pri);









#endif // SM2_H