#ifndef SM2_CERT_H
#define SM2_CERT_H

#include "sm2.h"

/* * 生成自签名 X.509 证书
 * * cert_pem: 输出缓冲区 (存放生成的 PEM 字符串)
 * max_len:  缓冲区最大长度
 * pub:      公钥
 * pri:      私钥 (用于给自己签名)
 * subject:  使用者名称 (如 "C=CN,O=Test,CN=User")
 * days:     有效期天数
 */
int sm2_create_cert_pem(char *cert_pem, int max_len,
                        const ec_point *pub, 
                        const bignum256 *pri,
                        const char *subject, 
                        int days);

#endif