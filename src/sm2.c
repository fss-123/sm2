#include "sm2.h"
#include <string.h>
#include <stdio.h>

/* 全局曲线参数 (简化处理，实际工程建议放入 Context) */
static sm2_curve_group group;
static int group_inited = 0;

/* 内部工具：确保曲线参数已加载 */
static void init_group() {
    if (!group_inited) {
        sm2_curve_init(&group);
        group_inited = 1;
    }
}

/* * [辅助宏] 将大数转为 32字节大端序二进制 (用于 SM3 哈希输入)
 * 因为 bignum256 内部是小端序，而 SM3 要求大端序字节流
 */
#define BN_TO_BYTES(bn, buf) do { \
    for(int i=0; i<8; i++) { \
        uint32_t w = (bn)->words[7-i]; \
        (buf)[i*4+0] = (uint8_t)(w >> 24); \
        (buf)[i*4+1] = (uint8_t)(w >> 16); \
        (buf)[i*4+2] = (uint8_t)(w >> 8);  \
        (buf)[i*4+3] = (uint8_t)(w); \
    } \
} while(0)

/* API: 生成密钥对 */
void sm2_keygen(sm2_key_pair *key, const char *pri_hex) {
    init_group();
    bn_read_string(&key->d, pri_hex);           // 1. 读取私钥 d
    ec_mul(&group, &key->P, &key->d, &group.G); // 2. 计算公钥 P = d * G
}

/* * [内部函数] 计算 ZA (用户身份预处理值的哈希)
 * 公式: ZA = SM3(ENTL || ID || a || b || xG || yG || xA || yA)
 * 这一步将曲线参数和用户身份绑定在一起
 */
static void sm2_compute_za(uint8_t *za,
                           const uint8_t *id, int id_len,
                           const ec_point *pub) {
    sm3_context ctx;
    sm3_init(&ctx);

    // 1. ENTL (ID 的比特长度，占2字节)
    uint8_t entl[2];
    entl[0] = (id_len * 8) >> 8;
    entl[1] = (id_len * 8) & 0xFF;
    sm3_update(&ctx, entl, 2);

    // 2. ID (用户标识)
    sm3_update(&ctx, id, id_len);

    // 3. 曲线参数 a, b, Gx, Gy
    uint8_t buf[32];
    BN_TO_BYTES(&group.a, buf); sm3_update(&ctx, buf, 32);
    BN_TO_BYTES(&group.b, buf); sm3_update(&ctx, buf, 32);
    
    bignum256 gx, gy;
    ec_to_affine(&group, &group.G, &gx, &gy); // 转为仿射坐标
    BN_TO_BYTES(&gx, buf); sm3_update(&ctx, buf, 32);
    BN_TO_BYTES(&gy, buf); sm3_update(&ctx, buf, 32);

    // 4. 公钥坐标 xA, yA
    bignum256 xA, yA;
    ec_to_affine(&group, pub, &xA, &yA);
    BN_TO_BYTES(&xA, buf); sm3_update(&ctx, buf, 32);
    BN_TO_BYTES(&yA, buf); sm3_update(&ctx, buf, 32);

    sm3_final(&ctx, za);
}

/* * API: SM2 数字签名
 * 流程参考: GB/T 32918.2-2016 第 6 章
 */
void sm2_sign(sm2_signature *sig,
              const uint8_t *msg, int msg_len,
              const uint8_t *id, int id_len,
              const ec_point *pub, const bignum256 *pri,
              const char *k_hex) 
{
    init_group();
    
    // Step 1: 计算 M' = ZA || M
    uint8_t za[32];
    sm2_compute_za(za, id, id_len, pub);
    
    // Step 2: 计算 e = SM3(M')
    sm3_context ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, za, 32);
    sm3_update(&ctx, msg, msg_len);
    
    uint8_t e_buf[32];
    sm3_final(&ctx, e_buf);
    
    // 将哈希值 e 转为大整数
    bignum256 e;
    char e_hex[65];
    for(int i=0; i<32; i++) sprintf(e_hex + i*2, "%02X", e_buf[i]);
    bn_read_string(&e, e_hex);

    // Step 3: 产生随机数 k (这里使用传入的 k)
    bignum256 k;
    bn_read_string(&k, k_hex);

    // Step 4: 计算椭圆曲线点 (x1, y1) = k * G
    ec_point xy1;
    ec_mul(&group, &xy1, &k, &group.G);
    
    bignum256 x1, y1;
    ec_to_affine(&group, &xy1, &x1, &y1); // 必须转回仿射坐标取 x1

    // Step 5: 计算 r = (e + x1) mod n
    // 注意：e + x1 可能会超过 256 位，但一定小于 2n
    // bignum256 tmp;
    // uint32_t carry = bn_add(&sig->r, &e, &x1);
    // if (carry || bn_cmp(&sig->r, &group.n) >= 0) {
    //     bn_sub(&sig->r, &sig->r, &group.n);
    // }
    uint32_t carry = bn_add(&sig->r, &e, &x1);
    if (carry) {
        // 发生了进位，说明结果 > 2^256 > n
        // 我们需要加上 (2^256 - n)
        bignum256 two_256_minus_n;
        // 2^256 - n 其实就是 n 的补码 (因为 n 是负数逻辑)
        // 或者更简单的：我们先减 n (会下溢产生 borrow)，然后自动抵消掉那个 carry
        // 计算机补码特性：(r - n) 在 carry=1 时就是正确答案
        bn_sub(&sig->r, &sig->r, &group.n); 
    } else if (bn_cmp(&sig->r, &group.n) >= 0) {
        // 没进位，但比 n 大，直接减
        bn_sub(&sig->r, &sig->r, &group.n);
    }
    
    // Step 6: 计算 s = (1 + d)^(-1) * (k - r*d) mod n
    
    // 6.1 计算 (1 + d)
    bignum256 one; bn_read_string(&one, "1");
    bignum256 d_plus_1;
    carry = bn_add(&d_plus_1, pri, &one);
    // 如果 d+1 >= n (极罕见，但要处理)，应减 n。这里假定 d < n-1。

    // 6.2 计算 (1 + d)^(-1) mod n
    bignum256 inv_d_1;
    bn_mod_inv(&inv_d_1, &d_plus_1, &group.n);
    
    // 6.3 计算 r * d
    bignum512 rd_512;
    bn_mul(&rd_512, &sig->r, pri); // 结果 512 位
    bignum256 rd;
    bn_mod(&rd, &rd_512, &group.n); // 模 n 变回 256 位
    
    // 6.4 计算 k - (r*d)
    bignum256 k_sub_rd;
    if (bn_cmp(&k, &rd) >= 0) {
        bn_sub(&k_sub_rd, &k, &rd); // k >= rd, 直接减
    } else {
        // k < rd, 也就是负数。在模运算里，负数要加上模数 n
        // k - rd = k + n - rd
        bn_add(&k_sub_rd, &k, &group.n);
        bn_sub(&k_sub_rd, &k_sub_rd, &rd);
    }
    
    // 6.5 最终 s = inv * (k - rd) mod n
    bignum512 s_512;
    bn_mul(&s_512, &inv_d_1, &k_sub_rd);
    bn_mod(&sig->s, &s_512, &group.n);
}

/* * API: SM2 验签
 * 流程参考: GB/T 32918.2-2016 第 7 章
 */
int sm2_verify(const sm2_signature *sig,
               const uint8_t *msg, int msg_len,
               const uint8_t *id, int id_len,
               const ec_point *pub) 
{
    init_group();
    
    // Step 1: 检查 r, s 是否在 [1, n-1] 之间 (简化省略，直接做计算)

    // Step 2: 计算消息哈希 e (必须与签名时完全一致)
    uint8_t za[32];
    sm2_compute_za(za, id, id_len, pub);
    
    sm3_context ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, za, 32);
    sm3_update(&ctx, msg, msg_len);
    
    uint8_t e_buf[32];
    sm3_final(&ctx, e_buf);
    
    bignum256 e;
    char e_hex[65];
    for(int i=0; i<32; i++) sprintf(e_hex + i*2, "%02X", e_buf[i]);
    bn_read_string(&e, e_hex);

    // Step 3: 计算 t = (r + s) mod n
    bignum256 t;
    uint32_t carry = bn_add(&t, &sig->r, &sig->s);
    if (carry || bn_cmp(&t, &group.n) >= 0) {
        bn_sub(&t, &t, &group.n);
    }
    
    // 如果 t=0，验证失败
    bignum256 zero; memset(&zero, 0, sizeof(zero));
    if (bn_cmp(&t, &zero) == 0) return 1;

    // Step 4: 计算点 (x1, y1) = s*G + t*P
    ec_point sG, tP, R_point;
    ec_mul(&group, &sG, &sig->s, &group.G); // s * G
    ec_mul(&group, &tP, &t, pub);           // t * P
    ec_add(&group, &R_point, &sG, &tP);     // 相加
    
    bignum256 x1, y1;
    ec_to_affine(&group, &R_point, &x1, &y1); // 取横坐标 x1
    
    // Step 5: 计算 R = (e + x1) mod n
    bignum256 calc_r;
    carry = bn_add(&calc_r, &e, &x1);
    if (carry || bn_cmp(&calc_r, &group.n) >= 0) {
        bn_sub(&calc_r, &calc_r, &group.n);
    }
    
    // Step 6: 比较计算出的 R 与签名中的 r 是否相等
    if (bn_cmp(&calc_r, &sig->r) == 0) {
        return 0; // 成功 (Verify Success)
    } else {
        return 1; // 失败 (Verify Failed)
    }
}


/* ==========================================================
 * SM2 密钥交换实现
 * ========================================================== */

/* * 内部工具: 标准 KDF (Key Derivation Function)
 * 算法: K = Hash(Z || 1) || Hash(Z || 2) ...
 */
static void sm2_kdf(uint8_t *out, int klen, const uint8_t *z, int zlen) {
    sm3_context ctx;
    uint8_t hash[32];
    int ct = 1; // 计数器，从 1 开始
    int offset = 0;

    while (offset < klen) {
        sm3_init(&ctx);
        sm3_update(&ctx, z, zlen);
        
        // 拼接计数器 (32位大端序)
        uint8_t ct_bytes[4];
        ct_bytes[0] = (ct >> 24) & 0xFF;
        ct_bytes[1] = (ct >> 16) & 0xFF;
        ct_bytes[2] = (ct >> 8) & 0xFF;
        ct_bytes[3] = ct & 0xFF;
        sm3_update(&ctx, ct_bytes, 4);
        
        sm3_final(&ctx, hash);

        // 拷贝结果
        int copy_len = (klen - offset > 32) ? 32 : (klen - offset);
        memcpy(out + offset, hash, copy_len);
        
        offset += copy_len;
        ct++;
    }
}

/* * 内部工具: 计算 x_bar
 * 规则: w = ceil(ceil(log2(n))/2) - 1. 对于 SM2, n是256位, w = 127
 * x_bar = 2^w + (x & (2^w - 1))
 * 简单说: 取 x 的低 127 位，然后第 128 位强制置 1
 */
static void sm2_calc_x_bar(bignum256 *x_bar, const bignum256 *x) {
    *x_bar = *x;
    
    // 1. 只保留低 127 位 (清除高位)
    // 127位 = words[0~2] (96bit) + words[3]的低31bit
    for (int i = 4; i < 8; i++) x_bar->words[i] = 0;
    x_bar->words[3] &= 0x7FFFFFFF;

    // 2. 第 128 位 (bit 127) 置 1
    // bit 127 对应 words[3] 的最高位
    x_bar->words[3] |= 0x80000000;
}

/* 密钥交换核心函数 */
void sm2_exchange_key(uint8_t *k_out, int k_len,
                      const uint8_t *self_id, int self_id_len,
                      const ec_point *self_pub, const bignum256 *self_pri,
                      const ec_point *self_tmp_pub, const bignum256 *self_tmp_pri,
                      const uint8_t *other_id, int other_id_len,
                      const ec_point *other_pub, const ec_point *other_tmp_pub)
{
    init_group();

    // 1. 计算双方的 ZA, ZB
    uint8_t za[32], zb[32];
    // 注意：这里传参稍微有点绕。算 ZA 用 self_id + self_pub
    sm2_compute_za(za, self_id, self_id_len, self_pub);
    // 算 ZB 用 other_id + other_pub
    sm2_compute_za(zb, other_id, other_id_len, other_pub);

    // 2. 计算 x_bar (对自己) 和 x_bar_other (对对方)
    // 只需要临时公钥的 x 坐标
    bignum256 x1_bar, x2_bar;
    bignum256 x_tmp;
    
    // 自己的 x1_bar
    // 必须先把 Jacobian 转回 Affine 才能取 x
    bignum256 y_tmp; 
    ec_to_affine(&group, self_tmp_pub, &x_tmp, &y_tmp);
    sm2_calc_x_bar(&x1_bar, &x_tmp);

    // 对方的 x2_bar
    ec_to_affine(&group, other_tmp_pub, &x_tmp, &y_tmp);
    sm2_calc_x_bar(&x2_bar, &x_tmp);

    // 3. 计算 t = (d_self + x1_bar * r_self) mod n
    bignum512 tmp_mul;
    bignum256 t, tmp_prod;
    
    bn_mul(&tmp_mul, &x1_bar, self_tmp_pri);
    bn_mod(&tmp_prod, &tmp_mul, &group.n); // x1_bar * r_self
    
    bn_add(&t, self_pri, &tmp_prod);       // d + ...
    if (bn_cmp(&t, &group.n) >= 0) bn_sub(&t, &t, &group.n);

    // 4. 计算 U = [h * t] (P_other + [x2_bar]R_other)
    // SM2 协因子 h = 1，所以 U = [t](P_other + [x2_bar]R_other)
    
    ec_point P_sum, P_mul_res;
    
    // 4.1 计算 [x2_bar]R_other
    ec_mul(&group, &P_mul_res, &x2_bar, other_tmp_pub);
    
    // 4.2 计算 P_other + ...
    ec_add(&group, &P_sum, other_pub, &P_mul_res);
    
    // 4.3 计算 U = [t]...
    ec_point U;
    ec_mul(&group, &U, &t, &P_sum);
    
    if (U.is_infinity) {
        // 协议规定：如果算出无穷远点，协商失败
        memset(k_out, 0, k_len);
        return; 
    }

    // 5. 计算 K = KDF(x_U || y_U || ZA || ZB, klen)
    bignum256 xu, yu;
    ec_to_affine(&group, &U, &xu, &yu);
    
    uint8_t buf[32];
    // 构造 KDF 的输入 Z
    // Z 大小 = 32(x) + 32(y) + 32(ZA) + 32(ZB) = 128 bytes
    uint8_t z_input[128];
    
    BN_TO_BYTES(&xu, buf); memcpy(z_input, buf, 32);
    BN_TO_BYTES(&yu, buf); memcpy(z_input + 32, buf, 32);
    memcpy(z_input + 64, za, 32);
    memcpy(z_input + 96, zb, 32);
    
    // 调用 KDF
    sm2_kdf(k_out, k_len, z_input, 128);
}


/* ==========================================================
 * SM2 加密与解密实现
 * 标准: GB/T 32918.4 (C1 || C3 || C2 模式)
 * ========================================================== */

/* * 复用之前的 sm2_kdf (确保它在 src/sm2.c 前面定义过)
 * 如果之前没定义，这里需要补上 KDF 函数。
 */

/* SM2 加密 */
int sm2_encrypt(uint8_t *out, 
                const uint8_t *msg, int msg_len,
                const ec_point *pub, 
                const char *k_hex)
{
    init_group();

    // 1. 产生随机数 k (测试用固定值)
    bignum256 k;
    if (k_hex) {
        bn_read_string(&k, k_hex);
    } else {
        // 生产环境应生成随机数，这里简化
        return 0; 
    }

    // 2. 计算 C1 = [k]G = (x1, y1)
    ec_point C1_point;
    ec_mul(&group, &C1_point, &k, &group.G);
    
    // 将 C1 转为字节串 (64字节: x||y)
    bignum256 x1, y1;
    ec_to_affine(&group, &C1_point, &x1, &y1);
    
    uint8_t c1_bytes[64];
    uint8_t buf_tmp[32];
    BN_TO_BYTES(&x1, buf_tmp); memcpy(c1_bytes, buf_tmp, 32);
    BN_TO_BYTES(&y1, buf_tmp); memcpy(c1_bytes + 32, buf_tmp, 32);

    // 3. 计算 [k]PB = (x2, y2)
    ec_point kP;
    ec_mul(&group, &kP, &k, pub);
    
    // 如果是无穷远点，报错
    if (kP.is_infinity) return 0;

    bignum256 x2, y2;
    ec_to_affine(&group, &kP, &x2, &y2);

    // 4. 计算 t = KDF(x2 || y2, klen)
    // t 的长度等于明文长度
    uint8_t *t = (uint8_t*)malloc(msg_len);
    if (!t) return 0;

    // 构造 KDF 输入 Z = x2 || y2
    uint8_t z[64];
    BN_TO_BYTES(&x2, buf_tmp); memcpy(z, buf_tmp, 32);
    BN_TO_BYTES(&y2, buf_tmp); memcpy(z + 32, buf_tmp, 32);
    
    sm2_kdf(t, msg_len, z, 64);

    // 5. 计算 C2 = M ^ t
    // 直接在 out 的对应位置写入 C2 (out 结构: C1[64] | C3[32] | C2[len])
    // C2 起始位置 = out + 64 + 32 = out + 96
    uint8_t *c2_ptr = out + 96;
    int all_zero = 1;
    for (int i = 0; i < msg_len; i++) {
        c2_ptr[i] = msg[i] ^ t[i];
        if (t[i] != 0) all_zero = 0;
    }
    free(t);
    if (all_zero) return 0; // 标准规定：如果 t 全为 0，需要重试 (这里简化报错)

    // 6. 计算 C3 = Hash(x2 || M || y2)
    sm3_context ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, z, 32);       // x2
    sm3_update(&ctx, msg, msg_len); // M
    sm3_update(&ctx, z + 32, 32);  // y2
    
    uint8_t c3_bytes[32];
    sm3_final(&ctx, c3_bytes);

    // 7. 拼接输出 C1 || C3 || C2
    memcpy(out, c1_bytes, 64);      // C1
    memcpy(out + 64, c3_bytes, 32); // C3 (注意位置在中间)
    // C2 已经在上面填好了

    return 1;
}

/* SM2 解密 */
int sm2_decrypt(uint8_t *plain,
                const uint8_t *cipher, int cipher_len,
                const bignum256 *pri)
{
    init_group();

    if (cipher_len < 96) return 0; // 长度不够
    int msg_len = cipher_len - 96;

    // 1. 取出 C1 (前 64 字节)
    char x1_hex[65], y1_hex[65];
    for(int i=0; i<32; i++) sprintf(x1_hex+i*2, "%02X", cipher[i]);
    for(int i=0; i<32; i++) sprintf(y1_hex+i*2, "%02X", cipher[i+32]);
    
    ec_point C1;
    bn_read_string(&C1.x, x1_hex);
    bn_read_string(&C1.y, y1_hex);
    bn_read_string(&C1.z, "1");
    C1.is_infinity = 0;

    // 验证 C1 是否在曲线上 (略，生产环境必须做)

    // 2. 计算 [d]C1 = (x2, y2)
    ec_point dC1;
    ec_mul(&group, &dC1, pri, &C1);
    
    if (dC1.is_infinity) return 0;
    
    bignum256 x2, y2;
    ec_to_affine(&group, &dC1, &x2, &y2);

    // 3. 计算 t = KDF(x2 || y2, klen)
    uint8_t *t = (uint8_t*)malloc(msg_len);
    if (!t) return 0;
    
    uint8_t z[64];
    uint8_t buf_tmp[32];
    BN_TO_BYTES(&x2, buf_tmp); memcpy(z, buf_tmp, 32);
    BN_TO_BYTES(&y2, buf_tmp); memcpy(z + 32, buf_tmp, 32);
    
    sm2_kdf(t, msg_len, z, 64);

    // 4. 计算 M = C2 ^ t
    const uint8_t *c2_ptr = cipher + 96;
    int all_zero = 1;
    for (int i = 0; i < msg_len; i++) {
        plain[i] = c2_ptr[i] ^ t[i];
        if (t[i] != 0) all_zero = 0;
    }
    free(t);
    if (all_zero) return 0;

    // 5. 计算 u = Hash(x2 || M || y2) 并比对 C3
    sm3_context ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, z, 32);        // x2
    sm3_update(&ctx, plain, msg_len); // M (刚才解出来的)
    sm3_update(&ctx, z + 32, 32);   // y2
    
    uint8_t u[32];
    sm3_final(&ctx, u);

    // 比对 C3 (cipher 中 64~95 字节)
    const uint8_t *c3_ptr = cipher + 64;
    if (memcmp(u, c3_ptr, 32) != 0) {
        return 0; // 校验失败
    }

    return 1; // 成功
}