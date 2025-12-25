#include <stdio.h>
#include "bignum.h"
#include "ec.h"
#include "sm2.h" // 引入新头文件

int main() {

    // === 自检程序 Start ===
    printf("[Sanity Check] Running internal diagnostics...\n");
    
    // 1. 检查 G 点是否正确加载
    sm2_curve_group g_test;
    sm2_curve_init(&g_test);
    printf("Check G.x word[0] (Expected C774...): %08x\n", g_test.G.x.words[0]); 
    // words[0] 是小端序的最低位，应该是 0x334C74C7 (字符串末尾)
    
    // 2. 检查 bn_mul 是否正确
    bignum256 ma, mb;
    bignum512 mres;
    bn_read_string(&ma, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    bn_read_string(&mb, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    bn_mul(&mres, &ma, &mb);
    // Max * Max 应该等于 FFFE...0001
    printf("Check Mul Max*Max (Expected Low=1): %08x\n", mres.words[0]);
    // === 自检程序 End ===

    printf("=== SM2: BigNum Math Base ===\n");

    bignum256 a, b, res;

    // ------------------------------------------
    // Test 1: 简单加法 (2 + 1)
    // ------------------------------------------
    printf("\n[Test 1] 2 + 1\n");
    bn_read_string(&a, "2"); // 自动补全前面的0
    bn_read_string(&b, "1");
    
    bn_add(&res, &a, &b);
    bn_print("Result", &res); // 期望: ...0003

    // ------------------------------------------
    // Test 2: 进位测试 (FFFF... + 1)
    // 验证多精度进位逻辑是否生效
    // ------------------------------------------
    printf("\n[Test 2] Max(FFFF...) + 1\n");
    // 输入一个全F的最大数
    bn_read_string(&a, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    bn_read_string(&b, "1");
    
    uint32_t carry = bn_add(&res, &a, &b);
    bn_print("Result", &res);       // 期望: 全 0
    printf("Carry : %d\n", carry);  // 期望: 1 (溢出)

    // ------------------------------------------
    // Test 3: 减法测试 (3 - 2)
    // ------------------------------------------
    printf("\n[Test 3] 3 - 2\n");
    bn_read_string(&a, "3");
    bn_read_string(&b, "2");
    
    bn_sub(&res, &a, &b);
    bn_print("Result", &res); // 期望: ...0001
    
    // ------------------------------------------
    // Test 4: 借位测试 (1 - 2)
    // 验证下溢逻辑
    // ------------------------------------------
    printf("\n[Test 4] 1 - 2 (Borrow Check)\n");
    bn_read_string(&a, "1");
    bn_read_string(&b, "2");
    
    uint32_t borrow = bn_sub(&res, &a, &b);
    bn_print("Result", &res);        // 期望: FFFF... (即 -1 的补码)
    printf("Borrow: %d\n", borrow);  // 期望: 1

    // ==========================================
    // 乘法与取模测试
    // ==========================================
    printf("\n=== SM2: Mul & Mod ===\n");

    bignum512 prod;
    
    // [Test 5] 乘法: 2 * 3 = 6
    printf("\n[Test 5] 2 * 3\n");
    bn_read_string(&a, "2");
    bn_read_string(&b, "3");
    bn_mul(&prod, &a, &b);
    
    // 我们暂时只能打印 bignum256，所以我们只看 prod 的低 256 位
    // 强制类型转换打印低位 (生产环境不建议这么干，但在测试里很方便)
    bn_print("Prod(L)", (bignum256*)&prod); // 期望: ...0006

    // [Test 6] 乘法溢出测试: Max * 2
    printf("\n[Test 6] Max * 2 (Should be 512-bit)\n");
    bn_read_string(&a, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    bn_read_string(&b, "2");
    bn_mul(&prod, &a, &b);
    
    // 结果应该是 FFFE... (低256位) 和 1 (高256位)
    // 我们可以手动查看高位 words[8]
    printf("Prod High Word: %08x\n", prod.words[8]); // 期望: 00000001
    bn_print("Prod Low Part ", (bignum256*)&prod);   // 期望: ...FFFE

    // [Test 7] 模运算: 20 % 7 = 6
    printf("\n[Test 7] 20 %% 7\n");
    bignum256 modulus, rem;
    
    // 构造 20 (通过乘法: 4 * 5 = 20)
    bn_read_string(&a, "4");
    bn_read_string(&b, "5");
    bn_mul(&prod, &a, &b); // prod = 20
    
    bn_read_string(&modulus, "7");
    
    bn_mod(&rem, &prod, &modulus);
    bn_print("20 % 7", &rem); // 期望: ...0006
    printf("=== SM2: Elliptic Curve Arithmetic ===\n");

    sm2_curve_group group;
    sm2_curve_init(&group);

    // [Test 8] 验证 2G = G + G
    printf("\n[Test 8] Check 2G = G + G\n");
    
    ec_point G_plus_G;
    ec_add(&group, &G_plus_G, &group.G, &group.G);
    
    ec_point Two_G;
    bignum256 k_two;
    bn_read_string(&k_two, "2");
    ec_mul(&group, &Two_G, &k_two, &group.G);
    
    // 转换回仿射坐标进行比较
    bignum256 x1, y1, x2, y2;
    ec_to_affine(&group, &G_plus_G, &x1, &y1);
    ec_to_affine(&group, &Two_G, &x2, &y2);
    
    bn_print("G+G (x)", &x1);
    bn_print("2*G (x)", &x2);
    
    if (bn_cmp(&x1, &x2) == 0 && bn_cmp(&y1, &y2) == 0) {
        printf(">>> PASS: Point Arithmetic Consistent\n");
    } else {
        printf(">>> FAIL: Mismatch\n");
    }

    // [Test 9] 验证 n * G = Infinity
    printf("\n[Test 9] Check n * G = O (Infinity)\n");
    ec_point NG;
    ec_mul(&group, &NG, &group.n, &group.G);
    
    if (NG.is_infinity) {
        printf(">>> PASS: n*G is Infinity (Correct Cycle)\n");
    } else {
        printf(">>> FAIL: n*G is NOT Infinity\n");
        ec_to_affine(&group, &NG, &x1, &y1);
        bn_print("Result X", &x1);
    }
    // ==========================================
    // 数字签名标准测试
    // ==========================================
    printf("\n=== SM2: Digital Signature (GM/T 0003.2) ===\n");

    /* * [标准测试向量] 来自 GM/T 0003.2-2012 附录 A
     * 场景: 用户 Alice 使用固定的私钥对消息 "message digest" 签名
     */

    sm2_key_pair key;
    // Alice 的私钥
    const char *pri_hex = "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263";
    sm2_keygen(&key, pri_hex); // 生成公钥

    // ---------------------------------------------------------
    // [诊断 1] 检查生成的公钥 P 是否符合标准
    // ---------------------------------------------------------
    bignum256 px, py;
    ec_to_affine(&group, &key.P, &px, &py); 
    printf("[Debug] Public Key Check:\n");
    bn_print("My P.x", &px);
    bn_print("My P.y", &py);
    // 标准公钥 (Standard Public Key)
    printf("Std P.x: 0ae4c7798aa0f119471bee11825be46202bb79e2a58bc7c505a7f306c3c30041\n");
    printf("Std P.y: 7d9029f198854529087f6d97e74527e2943a7c3f6213de408d29dc15d56a1300\n");
    // ---------------------------------------------------------

    // 原始消息和用户 ID
    const char *msg_str = "message digest";
    const char *id_str  = "ALICE123@YAHOO.COM";
    // 固定的随机数 k (为了复现标准结果)
    const char *k_hex   = "6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F";

    /* 标准答案 (Expected Result) */
    bignum256 exp_r, exp_s;
    bn_read_string(&exp_r, "40F1EC59F793D9F49E09DCEF49130D4194F79FB1EED2CAA55BACDB49C4E755D1");
    bn_read_string(&exp_s, "6FC6DAC32C5D5CF10C77DFB20F7C2EB667A457872FB09EC56327A67EC7DEEBE7");

    // 1. 执行签名
    sm2_signature sig;
    printf("Signing...\n");
    sm2_sign(&sig,
             (uint8_t*)msg_str, strlen(msg_str),
             (uint8_t*)id_str, strlen(id_str),
             &key.P, &key.d,
             k_hex);

    // 打印结果
    bn_print("Sign r", &sig.r);
    bn_print("Sign s", &sig.s);

    // 2. 对比结果
    if (bn_cmp(&sig.r, &exp_r) == 0 && bn_cmp(&sig.s, &exp_s) == 0) {
        printf(">>> PASS: Signature Matches Standard\n");
    } else {
        printf(">>> FAIL: Signature Mismatch\n");
    }

    // 3. 执行验签 (Self-Verify)
    printf("Verifying...\n");
    if (sm2_verify(&sig, 
                   (uint8_t*)msg_str, strlen(msg_str), 
                   (uint8_t*)id_str, strlen(id_str), 
                   &key.P) == 0) {
        printf(">>> PASS: Verify Success\n");
    } else {
        printf(">>> FAIL: Verify Failed\n");
    }


    // ==========================================
    // 密钥交换协议测试 (Alice & Bob)
    // ==========================================
    printf("\n=== SM2 Key Exchange Protocol ===\n");

    // 1. 初始化 Alice 的身份
    sm2_key_pair alice_long, alice_tmp;
    const char *id_a = "ALICE123@YAHOO.COM";
    // 长期密钥 (测试用固定值)
    sm2_keygen(&alice_long, "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263");
    // 临时密钥 (模拟随机生成)
    sm2_keygen(&alice_tmp,  "83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563");

    // 2. 初始化 Bob 的身份
    sm2_key_pair bob_long, bob_tmp;
    const char *id_b = "BILL456@YAHOO.COM";
    // 长期密钥
    sm2_keygen(&bob_long, "0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210");
    // 临时密钥
    sm2_keygen(&bob_tmp,  "6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F");

    // 3. 开始协商
    // 目标: 生成 16 字节 (128 bit) 的共享密钥，用于 SM4
    uint8_t key_a[16];
    uint8_t key_b[16];

    printf("Alice calculating shared key...\n");
    sm2_exchange_key(key_a, 16, 
                     (uint8_t*)id_a, strlen(id_a), &alice_long.P, &alice_long.d, &alice_tmp.P, &alice_tmp.d,
                     (uint8_t*)id_b, strlen(id_b), &bob_long.P, &bob_tmp.P);

    printf("Bob calculating shared key...\n");
    // 注意: Bob 视角的参数位置要反过来 (Self 是 Bob, Other 是 Alice)
    sm2_exchange_key(key_b, 16, 
                     (uint8_t*)id_b, strlen(id_b), &bob_long.P, &bob_long.d, &bob_tmp.P, &bob_tmp.d,
                     (uint8_t*)id_a, strlen(id_a), &alice_long.P, &alice_tmp.P);

    // 4. 打印并对比
    printf("Key A: ");
    for(int i=0; i<16; i++) printf("%02X", key_a[i]);
    printf("\n");

    printf("Key B: ");
    for(int i=0; i<16; i++) printf("%02X", key_b[i]);
    printf("\n");

    if (memcmp(key_a, key_b, 16) == 0) {
        printf(">>> PASS: Key Exchange Successful! Shared Secrets Match.\n");
    } else {
        printf(">>> FAIL: Keys do not match.\n");
    }


    // ==========================================
    // 公钥加密与解密 (Standard Test)
    // ==========================================
    printf("\n=== SM2 Day 6: Public Key Encryption ===\n");

    /* 标准测试向量 */
    const char *enc_pri_hex = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8";
    const char *enc_k_hex   = "59276E27D506861A16680F3ADB9ADE54A5F4F1359546D4B23260756B79091C36";
    const char *plain_text  = "encryption standard";
    int plain_len = strlen(plain_text);

    // 1. 初始化密钥
    sm2_key_pair enc_key;
    sm2_keygen(&enc_key, enc_pri_hex);

    // 2. 加密
    // 密文长度 = 96 (头) + 明文长度
    uint8_t ciphertext[200]; 
    printf("Encrypting...\n");
    if (sm2_encrypt(ciphertext, (uint8_t*)plain_text, plain_len, &enc_key.P, enc_k_hex)) {
        printf(">>> Encrypt Success\n");
        
        // 打印 C3 (中间 32 字节) 看看是否符合标准
        // 只是粗略看一眼
        printf("C3 (Hash): ");
        for(int i=64; i<70; i++) printf("%02X", ciphertext[i]);
        printf("...\n");
    } else {
        printf(">>> Encrypt Failed\n");
    }

    // 3. 解密
    uint8_t decrypted[200];
    memset(decrypted, 0, 200);
    printf("Decrypting...\n");
    if (sm2_decrypt(decrypted, ciphertext, 96 + plain_len, &enc_key.d)) {
        decrypted[plain_len] = '\0'; // 补零结束符
        printf("Decrypted Text: %s\n", decrypted);
        
        if (strcmp((char*)decrypted, plain_text) == 0) {
            printf(">>> PASS: Encryption/Decryption Loop\n");
        } else {
            printf(">>> FAIL: Decrypted text does not match\n");
        }
    } else {
        printf(">>> FAIL: Decrypt Failed (Hash Check Error)\n");
    }


    // ==========================================
    // 生成 X.509 证书 (Certificate)
    // ==========================================
    printf("\n=== SM2 Day 7: X.509 Certificate Generation ===\n");
    
    char cert_pem[8192];
    // 使用 Day 6 的加密密钥对来生成证书
    sm2_create_cert_pem(cert_pem, 8192, &enc_key.P, &enc_key.d, "CN=SM2User", 365);
    
    printf("Generated Certificate:\n%s\n", cert_pem);
    
    // 保存到文件
    FILE *fp = fopen("sm2_user.crt", "w");
    if (fp) {
        fprintf(fp, "%s", cert_pem);
        fclose(fp);
        printf(">>> Saved to 'sm2_user.crt'\n");
    } else {
        printf(">>> Failed to save file\n");
    }

    return 0;
}