#ifndef EC_H
#define EC_H

#include "bignum.h"

/* 雅可比坐标系下的点 (X, Y, Z) */
typedef struct {
    bignum256 x;
    bignum256 y;
    bignum256 z;
    int is_infinity; // 是否为无穷远点 (0:否, 1:是)
} ec_point;

/* SM2 曲线参数上下文 */
typedef struct {
    bignum256 p;  // 素数域 P
    bignum256 a;  // 曲线参数 a
    bignum256 b;  // 曲线参数 b
    bignum256 n;  // 阶 n
    ec_point  G;  // 基点 G
} sm2_curve_group;

/* API */

// 初始化并加载标准 SM2 参数
void sm2_curve_init(sm2_curve_group *group);

// 雅可比坐标 -> 仿射坐标 (X,Y,Z -> x,y)
void ec_to_affine(const sm2_curve_group *group, const ec_point *P, bignum256 *x, bignum256 *y);

// 点加: R = P + Q
void ec_add(const sm2_curve_group *group, ec_point *R, const ec_point *P, const ec_point *Q);

// 倍点: R = 2P
void ec_double(const sm2_curve_group *group, ec_point *R, const ec_point *P);

// 点乘: R = k * P (标量乘法)
void ec_mul(const sm2_curve_group *group, ec_point *R, const bignum256 *k, const ec_point *P);

#endif // EC_H