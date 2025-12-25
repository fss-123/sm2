#include "ec.h"
#include <string.h>

/* * 初始化 SM2 标准曲线参数 
 * 包含 P, a, b, n, G, Gx, Gy
 */
void sm2_curve_init(sm2_curve_group *group) {
    // 素数域 P
    bn_read_string(&group->p, "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF");
    // 参数 a
    bn_read_string(&group->a, "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC");
    // 参数 b
    bn_read_string(&group->b, "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93");
    // 阶 n
    bn_read_string(&group->n, "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123");
    
    // 基点 G 的坐标
    bn_read_string(&group->G.x, "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7");
    bn_read_string(&group->G.y, "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0");
    // 雅可比坐标 Z 初始化为 1
    bn_read_string(&group->G.z, "1");
    group->G.is_infinity = 0;
}

/* * [模加] r = a + b % p 
 */
static void fp_add(const sm2_curve_group *group, bignum256 *r, const bignum256 *a, const bignum256 *b) {
    uint32_t carry = bn_add(r, a, b);
    // 如果溢出或者结果 >= p，减去 p
    if (carry || bn_cmp(r, &group->p) >= 0) {
        bn_sub(r, r, &group->p);
    }
}

/* * [模减] r = a - b % p 
 * 修复说明: 这里是之前导致公钥算错的地方。
 * 必须检查 borrow，如果发生借位，必须加上 p，而不是用 overflow 的方法。
 */
static void fp_sub(const sm2_curve_group *group, bignum256 *r, const bignum256 *a, const bignum256 *b) {
    uint32_t borrow = bn_sub(r, a, b);
    // 如果发生借位 (a < b)，结果是负数，需要加 p 把它拉回正数范围
    if (borrow) {
        bn_add(r, r, &group->p);
    }
}

/* [模乘] r = a * b % p */
static void fp_mul(const sm2_curve_group *group, bignum256 *r, const bignum256 *a, const bignum256 *b) {
    bignum512 tmp;
    bn_mul(&tmp, a, b);
    bn_mod(r, &tmp, &group->p);
}

/* [模平方] r = a^2 % p */
static void fp_sqr(const sm2_curve_group *group, bignum256 *r, const bignum256 *a) {
    fp_mul(group, r, a, a);
}

/* * [坐标转换] 雅可比坐标 (X,Y,Z) -> 仿射坐标 (x,y)
 * 公式: x = X / Z^2, y = Y / Z^3
 */
void ec_to_affine(const sm2_curve_group *group, const ec_point *P, bignum256 *x, bignum256 *y) {
    if (P->is_infinity) {
        memset(x, 0, sizeof(bignum256));
        memset(y, 0, sizeof(bignum256));
        return;
    }
    bignum256 z_inv, z2, z3;
    bn_mod_inv(&z_inv, &P->z, &group->p); // 计算 Z 的逆元
    
    fp_sqr(group, &z2, &z_inv);       // z^-2
    fp_mul(group, &z3, &z2, &z_inv);  // z^-3
    
    fp_mul(group, x, &P->x, &z2);     // x = X * z^-2
    fp_mul(group, y, &P->y, &z3);     // y = Y * z^-3
}

/* * [倍点] R = 2P 
 * 实现了标准的 Jacobian 倍点公式
 */
void ec_double(const sm2_curve_group *group, ec_point *R, const ec_point *P) {
    if (P->is_infinity) { *R = *P; return; }

    bignum256 T1, T2, T3, Y2, Z2, M, S;
    bignum256 three; bn_read_string(&three, "3");

    fp_sqr(group, &Z2, &P->z);              // Z^2
    fp_sub(group, &T1, &P->x, &Z2);         // X - Z^2
    fp_add(group, &T2, &P->x, &Z2);         // X + Z^2
    fp_mul(group, &T3, &T1, &T2);           // (X-Z^2)(X+Z^2)
    fp_mul(group, &M, &T3, &three);         // M = 3 * ...

    fp_sqr(group, &Y2, &P->y);              // Y^2
    fp_mul(group, &T1, &P->x, &Y2);         // XY^2
    fp_add(group, &T1, &T1, &T1);           // 2XY^2
    fp_add(group, &S, &T1, &T1);            // 4XY^2 = S

    fp_sqr(group, &R->x, &M);               // M^2
    fp_sub(group, &R->x, &R->x, &S);        // M^2 - S
    fp_sub(group, &R->x, &R->x, &S);        // R.x = M^2 - 2S

    fp_sub(group, &T3, &S, &R->x);          // S - R.x
    fp_mul(group, &R->y, &M, &T3);          // M(S - R.x)
    
    fp_sqr(group, &T2, &Y2);                // Y^4
    fp_add(group, &T2, &T2, &T2);
    fp_add(group, &T2, &T2, &T2);           // 8Y^4
    fp_add(group, &T2, &T2, &T2);
    
    fp_sub(group, &R->y, &R->y, &T2);       // R.y

    fp_mul(group, &R->z, &P->y, &P->z);     // YZ
    fp_add(group, &R->z, &R->z, &R->z);     // 2YZ
    
    R->is_infinity = 0;
}

/* * [点加] R = P + Q 
 */
void ec_add(const sm2_curve_group *group, ec_point *R, const ec_point *P, const ec_point *Q) {
    if (P->is_infinity) { *R = *Q; return; }
    if (Q->is_infinity) { *R = *P; return; }

    bignum256 U1, U2, S1, S2, H, r;
    bignum256 Z1Z1, Z2Z2, tmp;

    fp_sqr(group, &Z2Z2, &Q->z);
    fp_mul(group, &U1, &P->x, &Z2Z2);       // U1
    
    fp_sqr(group, &Z1Z1, &P->z);
    fp_mul(group, &U2, &Q->x, &Z1Z1);       // U2
    
    fp_mul(group, &tmp, &Q->z, &Z2Z2);
    fp_mul(group, &S1, &P->y, &tmp);        // S1
    
    fp_mul(group, &tmp, &P->z, &Z1Z1);
    fp_mul(group, &S2, &Q->y, &tmp);        // S2
    
    fp_sub(group, &H, &U2, &U1);
    fp_sub(group, &r, &S2, &S1);
    
    // 如果 H=0，说明 x1=x2，可能是 P=Q 或 P=-Q
    bignum256 zero; memset(&zero, 0, sizeof(zero));
    if (bn_cmp(&H, &zero) == 0) {
        if (bn_cmp(&r, &zero) == 0) {
            ec_double(group, R, P); // P == Q
            return;
        } else {
            R->is_infinity = 1;     // P == -Q
            return;
        }
    }
    
    bignum256 H2, H3, U1H2;
    fp_sqr(group, &H2, &H);
    fp_mul(group, &H3, &H2, &H);
    fp_mul(group, &U1H2, &U1, &H2);
    
    fp_sqr(group, &R->x, &r);
    fp_sub(group, &R->x, &R->x, &H3);
    fp_sub(group, &R->x, &R->x, &U1H2);
    fp_sub(group, &R->x, &R->x, &U1H2);     // R.x
    
    fp_sub(group, &tmp, &U1H2, &R->x);
    fp_mul(group, &R->y, &r, &tmp);
    fp_mul(group, &tmp, &S1, &H3);
    fp_sub(group, &R->y, &R->y, &tmp);      // R.y
    
    fp_mul(group, &R->z, &P->z, &Q->z);
    fp_mul(group, &R->z, &R->z, &H);        // R.z
    
    R->is_infinity = 0;
}

/* * [点乘] R = k * P 
 * 算法: 二进制展开法 (Double-and-Add)
 */
void ec_mul(const sm2_curve_group *group, ec_point *R, const bignum256 *k, const ec_point *P) {
    ec_point Q;
    Q.is_infinity = 1; 
    ec_point Temp = *P;
    
    for (int i = 0; i < 256; i++) {
        int word_idx = i / 32;
        int bit_idx = i % 32;
        // 如果当前 bit 为 1，则加
        if ((k->words[word_idx] >> bit_idx) & 1) {
            ec_point next_Q;
            ec_add(group, &next_Q, &Q, &Temp);
            Q = next_Q;
        }
        // 每一轮都翻倍
        ec_point next_Temp;
        ec_double(group, &next_Temp, &Temp);
        Temp = next_Temp;
    }
    *R = Q;
}