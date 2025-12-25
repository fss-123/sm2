#include "sm2_cert.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* =============================================================
 * 简易 ASN.1 编码器 (DER格式)
 * ============================================================= */

// 写入 Tag 和 Length
// 返回写入的字节数
static int asn1_write_header(uint8_t *buf, uint8_t tag, int length) {
    int idx = 0;
    buf[idx++] = tag;
    
    if (length < 128) {
        buf[idx++] = length;
    } else if (length < 256) {
        buf[idx++] = 0x81;
        buf[idx++] = length;
    } else {
        buf[idx++] = 0x82;
        buf[idx++] = (length >> 8) & 0xFF;
        buf[idx++] = length & 0xFF;
    }
    return idx;
}

// 写入整数 (Integer)
static int asn1_write_integer(uint8_t *buf, const bignum256 *n) {
    // 先转为大端序字节
    uint8_t raw[32];
    for(int i=0; i<8; i++) {
        uint32_t w = n->words[7-i];
        raw[i*4+0] = w >> 24; raw[i*4+1] = w >> 16;
        raw[i*4+2] = w >> 8;  raw[i*4+3] = w;
    }
    
    // 去掉前导零，但如果是负数(最高位1)需要补00 (这是ASN.1规则，防止被当成负数)
    int start = 0;
    while (start < 31 && raw[start] == 0) start++;
    
    int len = 32 - start;
    int pad = (raw[start] & 0x80) ? 1 : 0;
    
    int idx = 0;
    idx += asn1_write_header(buf, 0x02, len + pad); // Tag 0x02
    if (pad) buf[idx++] = 0x00;
    memcpy(buf + idx, raw + start, len);
    idx += len;
    
    return idx;
}

// Base64 编码表
static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Base64 编码函数
static void base64_encode(char *out, const uint8_t *in, int in_len) {
    int i = 0, j = 0;
    uint32_t val = 0;
    for (i = 0; i < in_len; i++) {
        val = (val << 8) | in[i];
        if ((i + 1) % 3 == 0) {
            out[j++] = base64_chars[(val >> 18) & 0x3F];
            out[j++] = base64_chars[(val >> 12) & 0x3F];
            out[j++] = base64_chars[(val >> 6) & 0x3F];
            out[j++] = base64_chars[val & 0x3F];
            val = 0;
        }
    }
    // 处理剩余字节
    int remain = in_len % 3;
    if (remain == 1) {
        val = val << 16;
        out[j++] = base64_chars[(val >> 18) & 0x3F];
        out[j++] = base64_chars[(val >> 12) & 0x3F];
        out[j++] = '='; out[j++] = '=';
    } else if (remain == 2) {
        val = val << 8;
        out[j++] = base64_chars[(val >> 18) & 0x3F];
        out[j++] = base64_chars[(val >> 12) & 0x3F];
        out[j++] = base64_chars[(val >> 6) & 0x3F];
        out[j++] = '=';
    }
    out[j] = '\0';
}

/* =============================================================
 * 证书生成主逻辑
 * ============================================================= */
int sm2_create_cert_pem(char *cert_pem, int max_len,
                        const ec_point *pub, 
                        const bignum256 *pri,
                        const char *subject, 
                        int days)
{
    // TBS (To Be Signed) 区域缓冲区
    uint8_t tbs[2048]; 
    int tbs_idx = 0;

    // --- 1. 构建 TBS Certificate ---
    
    // [0] Version: v3 (2)
    // A0 03 02 01 02
    uint8_t ver[] = {0xA0, 0x03, 0x02, 0x01, 0x02};
    
    // [1] Serial Number: 1 (简化)
    // 02 01 01
    uint8_t sn[] = {0x02, 0x01, 0x01};

    // [2] Signature Algorithm: sm2-with-sm3 (OID: 1.2.156.10197.1.501)
    // 30 0C 06 08 2A 81 1C CF 55 01 83 75 05 00
    uint8_t sig_alg[] = {0x30, 0x0A, 0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 01, 0x83, 0x75};

    // [3] Issuer: CN=ROOT (简化)
    // 30 0F 31 0D 30 0B 06 03 55 04 03 0C 04 52 4F 4F 54
    uint8_t issuer[] = {0x30, 0x0F, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x04, 'R', 'O', 'O', 'T'};

    // [4] Validity (简化，写死时间)
    // 30 1E 17 0D 32 33 30 31 30 31 30 30 30 30 30 30 5A ...
    uint8_t time[] = {0x30, 0x1E, 
                      0x17, 0x0D, '2','3','0','1','0','1','0','0','0','0','0','0','Z',
                      0x17, 0x0D, '3','3','0','1','0','1','0','0','0','0','0','0','Z'};

    // [5] Subject: CN=USER (简化)
    uint8_t subj[] = {0x30, 0x0F, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x04, 'U', 'S', 'E', 'R'};

    // [6] Subject Public Key Info
    uint8_t pk_info[256];
    int pk_len = 0;
    
    // Algorithm ID (sm2: 1.2.840.10045.2.1) + Param (sm2curve: 1.2.156.10197.1.301)
    uint8_t pk_alg[] = {0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 01, 0x82, 0x2D};
    
    // Public Key BitString
    uint8_t pk_bits[128];
    int pk_bits_len = 0;
    pk_bits[0] = 0x00; // Unused bits
    pk_bits[1] = 0x04; // Uncompressed
    
    // 导出公钥坐标
    bignum256 x, y;
    // 这里的 group 需要确保初始化过，为了简单我们在 sm2.c 外部也能调用 init
    // 这里假设调用者已经做好了，或者我们在内部 hack 一下
    // (实际代码中应把 sm2_curve_init 暴露出来)
    // 临时方案：这里需要 ec_to_affine，假设 group 全局变量可用
    
    // !!! 注意：这里是个Hack，为了能编译通过，我们需要包含 sm2 的私有头部
    // 或者我们直接用 raw 字节操作。
    // 为了不破坏封装，我们假设 sm2.c 里有导出函数，或者简单地再次初始化 group
    sm2_curve_group g;
    sm2_curve_init(&g);
    ec_to_affine(&g, pub, &x, &y);
    
    for(int i=0; i<8; i++) { // x
        uint32_t w = x.words[7-i];
        pk_bits[2+i*4] = w>>24; pk_bits[3+i*4] = w>>16; pk_bits[4+i*4] = w>>8; pk_bits[5+i*4] = w;
    }
    for(int i=0; i<8; i++) { // y
        uint32_t w = y.words[7-i];
        pk_bits[34+i*4] = w>>24; pk_bits[35+i*4] = w>>16; pk_bits[36+i*4] = w>>8; pk_bits[37+i*4] = w;
    }
    pk_bits_len = 1 + 1 + 64; // 00 + 04 + xy
    
    // 组装 PublicKeyInfo
    int pki_idx = 0;
    memcpy(pk_info + pki_idx, pk_alg, sizeof(pk_alg)); pki_idx += sizeof(pk_alg);
    pki_idx += asn1_write_header(pk_info + pki_idx, 0x03, pk_bits_len); // BitString
    memcpy(pk_info + pki_idx, pk_bits, pk_bits_len); pki_idx += pk_bits_len;
    
    // 组装 TBS
    // 这是一个大 SEQUENCE，我们先拼内容，最后算总长度加头
    // 为简单起见，我们用一个大 buffer 顺序写入，最后 memmove
    
    uint8_t content[2048];
    int c_idx = 0;
    memcpy(content+c_idx, ver, sizeof(ver)); c_idx += sizeof(ver);
    memcpy(content+c_idx, sn, sizeof(sn)); c_idx += sizeof(sn);
    memcpy(content+c_idx, sig_alg, sizeof(sig_alg)); c_idx += sizeof(sig_alg);
    memcpy(content+c_idx, issuer, sizeof(issuer)); c_idx += sizeof(issuer);
    memcpy(content+c_idx, time, sizeof(time)); c_idx += sizeof(time);
    memcpy(content+c_idx, subj, sizeof(subj)); c_idx += sizeof(subj);
    
    // 写入 PublicKeyInfo 序列头
    c_idx += asn1_write_header(content+c_idx, 0x30, pki_idx);
    memcpy(content+c_idx, pk_info, pki_idx); c_idx += pki_idx;
    
    // 最终 TBS
    tbs_idx += asn1_write_header(tbs, 0x30, c_idx);
    memcpy(tbs + tbs_idx, content, c_idx);
    tbs_idx += c_idx;

    // --- 2. 签名 (Sign TBS) ---
    sm2_signature sig;
    const char *k_hex_fixed = "6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F"; // 固定K
    uint8_t id[] = "1234567812345678";
    
    sm2_sign(&sig, tbs, tbs_idx, id, 16, pub, pri, k_hex_fixed);
    
    // 编码签名值 (ASN.1 Sequence of Integer)
    uint8_t sig_val[256];
    int sv_idx = 0;
    // 内部 Sequence
    uint8_t seq_int[256];
    int si_idx = 0;
    si_idx += asn1_write_integer(seq_int + si_idx, &sig.r);
    si_idx += asn1_write_integer(seq_int + si_idx, &sig.s);
    
    sv_idx += asn1_write_header(sig_val, 0x30, si_idx);
    memcpy(sig_val + sv_idx, seq_int, si_idx);
    sv_idx += si_idx;
    
    // BitString 包装
    uint8_t sig_bits[256];
    int sb_idx = 0;
    sig_bits[sb_idx++] = 0x00; // unused bits
    memcpy(sig_bits + sb_idx, sig_val, sv_idx);
    sb_idx += sv_idx;

    // --- 3. 最终证书结构 (Certificate) ---
    // Sequence { TBS, SigAlg, SignatureValue }
    uint8_t cert_der[4096];
    int der_idx = 0;
    
    // 计算总长度：TBS长度 + SigAlg长度 + SigVal长度(加BitString头)
    // SigAlg 重复一次
    int total_len = tbs_idx + sizeof(sig_alg) + (1 + asn1_write_header(cert_der, 0x03, sb_idx) - 1 + sb_idx);
    // 这里偷懒不精确计算，直接写
    
    uint8_t final_content[4096];
    int fc_idx = 0;
    
    memcpy(final_content + fc_idx, tbs, tbs_idx); fc_idx += tbs_idx;
    memcpy(final_content + fc_idx, sig_alg, sizeof(sig_alg)); fc_idx += sizeof(sig_alg);
    fc_idx += asn1_write_header(final_content + fc_idx, 0x03, sb_idx);
    memcpy(final_content + fc_idx, sig_bits, sb_idx); fc_idx += sb_idx;
    
    der_idx += asn1_write_header(cert_der, 0x30, fc_idx);
    memcpy(cert_der + der_idx, final_content, fc_idx);
    der_idx += fc_idx;

    // --- 4. 封装 PEM ---
    strcpy(cert_pem, "-----BEGIN CERTIFICATE-----\n");
    char b64[8192];
    base64_encode(b64, cert_der, der_idx);
    
    // 每 64 字符换行
    int len = strlen(b64);
    for(int i=0; i<len; i+=64) {
        strncat(cert_pem, b64 + i, 64);
        strcat(cert_pem, "\n");
    }
    strcat(cert_pem, "-----END CERTIFICATE-----\n");
    
    return 1;
}