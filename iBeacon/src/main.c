/*
 * SPDX-FileCopyrightText: 2024-2024 SiFli Technologies(Nanjing) Co., Ltd
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rtthread.h>
#include <rtdevice.h>
#include <board.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "bf0_ble_gap.h"
#include "bf0_sibles.h"
#include "bf0_sibles_internal.h"
#include "bf0_sibles_advertising.h"
#include "ble_connection_manager.h"

// mbedTLS:用于 AES-ECB 加解密、椭圆曲线、大整数运算
#include "mbedtls/aes.h"
#include "mbedtls/bignum.h"

// FMDN 共享接口(常量、app_env_t、对外导出的核心函数)
#include "fmdn.h"
// FMDN 挑战-应答认证模块(HMAC / AuthKey 校验 / nonce 生命周期)
#include "fmdn_auth.h"
// FMDN 配网状态持久化模块(AK / EIK / 配网标志 存入 flash)
#include "fmdn_store.h"
// FMDN 硬件随机数(TRNG)封装(nonce 随机源)
#include "fmdn_rng.h"


#define LOG_TAG "ble_app"
#include "log.h"

// ############################################################
// #  文件结构
// #    main.c            — FMDN 核心(本文件):
// #                        加解密 / EID 引擎 / 广播 / GATT / 主流程
// #    fmdn_test_cmds.c  — 串口测试与调试命令(cmd_fmdn_*)
// #    fmdn.h            — 两者之间的共享接口
// ############################################################

// ============================================================
// FMDN GATT 服务:Fast Pair Beacon Actions
// ============================================================
// 服务 UUID: 0xFE2C (Fast Pair)
// 特征 UUID: FE2C1238-8366-4814-8EB0-01DE32100BEA (Beacon Actions)
// 属性:     读 / 写 / 通知(无加密)
//
// 挑战-应答流程:
//   1. 手机 READ   → 设备返回 [版本(1B) | Nonce(8B)]
//   2. 手机 WRITE  → [DataID(1B)|DataLen(1B)|AuthKey(8B)|附加数据...]
//   3. 设备 NOTIFY → [DataID(1B)|DataLen(1B)|VerifyKey(8B)|响应...]
// ============================================================

enum fmdn_gatt_att_list
{
    FMDN_SVC,           // 服务声明 (0x2800)
    FMDN_CHAR,          // 特征声明 (0x2803)
    FMDN_BEACON_ACTIONS,// Beacon Actions 特征值
    FMDN_CCCD,          // 客户端特征配置描述符 (CCCD)
    FMDN_ATT_NB
};

#define SERIAL_UUID_16(x) {((uint8_t)(x&0xff)),((uint8_t)(x>>8))}

// Fast Pair 服务 UUID:0xFE2C(16 位,封装进 128 位基础 UUID)
#define FP_SERVICE_UUID { \
    0xFB, 0x34, 0x9B, 0x5F, 0x80, 0x00, 0x00, 0x80, \
    0x00, 0x10, 0x00, 0x00, 0x2C, 0xFE, 0x00, 0x00  \
}

// Beacon Actions 特征 UUID:FE2C1238-8366-4814-8EB0-01DE32100BEA
// BLE 的 128 位 UUID 在线上是完整小端:16 个字节是标准 UUID 字节的整段倒序(LSB 在前)。
//   UUID(高位..低位): FE 2C 12 38 83 66 48 14 8E B0 01 DE 32 10 0B EA
//   线上(小端):      EA 0B 10 32 DE 01 B0 8E 14 48 66 83 38 12 2C FE
#define BEACON_ACTIONS_UUID { \
    0xEA, 0x0B, 0x10, 0x32, \
    0xDE, 0x01, 0xB0, 0x8E, \
    0x14, 0x48, 0x66, 0x83, \
    0x38, 0x12, 0x2C, 0xFE  \
}

static uint8_t g_fp_service_uuid[ATT_UUID_128_LEN] = FP_SERVICE_UUID;

BLE_GATT_SERVICE_DEFINE_128(fmdn_att_db)
{
    BLE_GATT_SERVICE_DECLARE(FMDN_SVC, SERIAL_UUID_16_PRI_SERVICE, BLE_GATT_PERM_READ_ENABLE),
    BLE_GATT_CHAR_DECLARE(FMDN_CHAR, SERIAL_UUID_16_CHARACTERISTIC, BLE_GATT_PERM_READ_ENABLE),
    BLE_GATT_CHAR_VALUE_DECLARE(FMDN_BEACON_ACTIONS, BEACON_ACTIONS_UUID,
            BLE_GATT_PERM_READ_ENABLE | BLE_GATT_PERM_WRITE_REQ_ENABLE |
            BLE_GATT_PERM_WRITE_COMMAND_ENABLE | BLE_GATT_PERM_NOTIFY_ENABLE,
            BLE_GATT_VALUE_PERM_UUID_128 | BLE_GATT_VALUE_PERM_RI_ENABLE,
            64),   // 挑战-应答最大 64 字节
    BLE_GATT_DESCRIPTOR_DECLARE(FMDN_CCCD, SERIAL_UUID_16_CLIENT_CHAR_CFG,
            BLE_GATT_PERM_READ_ENABLE | BLE_GATT_PERM_WRITE_REQ_ENABLE,
            BLE_GATT_VALUE_PERM_RI_ENABLE, 2),
};

// FMDN 操作 Data ID(FMDN_DATA_ID_*)已移至 fmdn.h(与测试/认证模块共享)

// FMDN_PROTOCOL_VERSION / FMDN_NONCE_LEN / FMDN_EID_LEN / FMDN_EID_ROTATION_K
// 以及 app_env_t、fmdn_nonce_t 均声明在 fmdn.h 中(与测试/认证模块共享)。

static app_env_t g_app_env;

app_env_t *ble_app_get_env(void)
{
    return &g_app_env;
}

SIBLES_ADVERTISING_CONTEXT_DECLAR(g_app_advertising_context);

static uint8_t ble_app_advertising_event(uint8_t event, void *context, void *data)
{
    app_env_t *env = ble_app_get_env();

    switch (event)
    {
    case SIBLES_ADV_EVT_ADV_STARTED:
    {
        sibles_adv_evt_startted_t *evt = (sibles_adv_evt_startted_t *)data;
        LOG_I("ADV start result %d, mode %d\r\n", evt->status, evt->adv_mode);
        break;
    }
    case SIBLES_ADV_EVT_ADV_STOPPED:
    {
        sibles_adv_evt_stopped_t *evt = (sibles_adv_evt_stopped_t *)data;
        LOG_I("ADV stopped reason %d, mode %d\r\n", evt->reason, evt->adv_mode);
        break;
    }
    default:
        break;
    }
    return 0;
}

// ============================================================
// FMDN(Find My Device Network)广播帧
// ============================================================
// 帧格式(Service Data AD 类型 0x16,服务 UUID 0xFEAA):
//   [0]    AD 长度 = 0x18(24 字节:1 字节 AD 类型 + 23 字节负载)
//   [1]    AD 类型 = 0x16(Service Data - 16 位 UUID)
//   [2-3]  服务 UUID = 0xFEAA(小端:AA, FE)
//   [4]    UT 字节 = 0x40(UT 关)或 0x41(UT 开)
//   [5-24] EID = 20 字节临时标识符
// ============================================================

#define FMDN_SERVICE_UUID    0xFEAA
#define FMDN_AD_PAYLOAD_LEN  23        // 2(UUID) + 1(UT) + 20(EID) = 23(AD 类型之后的负载)
#define FMDN_AD_TOTAL_LEN    24        // 1(AD 类型) + 23(负载) = 24(AD 长度字段值)
#define FMDN_UT_OFF          0x40
#define FMDN_UT_ON           0x41

static void fmdn_frame_build(uint8_t *data, uint8_t ut_byte, const uint8_t eid[20])
{
    // AD 长度 = 1(AD 类型) + 2(UUID) + 1(UT) + 20(EID) = 24
    data[0] = FMDN_AD_TOTAL_LEN;       // 24 = 0x18
    // AD 类型:Service Data - 16 位 UUID
    data[1] = 0x16;
    // 服务 UUID 0xFEAA(小端)
    data[2] = (uint8_t)(FMDN_SERVICE_UUID & 0xFF);       // 0xAA
    data[3] = (uint8_t)((FMDN_SERVICE_UUID >> 8) & 0xFF); // 0xFE
    // UT 字节
    data[4] = ut_byte;
    // EID(20 字节)
    rt_memcpy(&data[5], eid, 20);
}

// ============================================================
// AES-ECB-128 辅助函数(基于 mbedTLS)
// ============================================================
// AES-ECB 对单个 16 字节块加/解密。
// 多块数据(如 32 字节 EIK)需逐块调用。

int aes_ecb_128_crypt(const uint8_t key[16], const uint8_t input[16],
                      uint8_t output[16], int mode)
{
    mbedtls_aes_context ctx;
    int ret;

    mbedtls_aes_init(&ctx);
    if (mode == MBEDTLS_AES_ENCRYPT)
        ret = mbedtls_aes_setkey_enc(&ctx, key, 128);
    else
        ret = mbedtls_aes_setkey_dec(&ctx, key, 128);

    if (ret != 0)
    {
        LOG_E("AES setkey failed: %d", ret);
        mbedtls_aes_free(&ctx);
        return ret;
    }

    ret = mbedtls_aes_crypt_ecb(&ctx, mode, input, output);
    mbedtls_aes_free(&ctx);

    if (ret != 0)
        LOG_E("AES ECB failed: %d", ret);
    return ret;
}

// 用 Account Key 通过 AES-ECB-128 解密 EIK(32 字节,分 2 块)
static int fmdn_decrypt_eik(const uint8_t account_key[16],
                             const uint8_t encrypted_eik[32],
                             uint8_t decrypted_eik[32])
{
    int ret;

    // 第 1 块:字节 0-15
    ret = aes_ecb_128_crypt(account_key, &encrypted_eik[0],
                             &decrypted_eik[0], MBEDTLS_AES_DECRYPT);
    if (ret != 0) return ret;

    // 第 2 块:字节 16-31
    ret = aes_ecb_128_crypt(account_key, &encrypted_eik[16],
                             &decrypted_eik[16], MBEDTLS_AES_DECRYPT);
    return ret;
}

// ============================================================
// AES-ECB-256 加密两个 16 字节块(用于 EID 生成)
// EIK = 32 字节 = 256 位密钥
// ============================================================
int aes_ecb_256_encrypt_block32(const uint8_t key_256[32],
                                        const uint8_t plain[32],
                                        uint8_t cipher[32])
{
    mbedtls_aes_context ctx;
    int ret;

    mbedtls_aes_init(&ctx);
    ret = mbedtls_aes_setkey_enc(&ctx, key_256, 256);
    if (ret != 0)
    {
        LOG_E("AES-256 setkey failed: %d", ret);
        mbedtls_aes_free(&ctx);
        return ret;
    }

    // 第 1 块:字节 0-15
    ret = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT,
                                 &plain[0], &cipher[0]);
    if (ret != 0) { mbedtls_aes_free(&ctx); return ret; }

    // 第 2 块:字节 16-31
    ret = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT,
                                 &plain[16], &cipher[16]);
    mbedtls_aes_free(&ctx);
    return ret;
}

// ============================================================
// 模块:SECP160R1 椭圆曲线 —— 基于 mbedTLS 大整数的精简实现
// ============================================================
// 曲线:y^2 = x^3 + ax + b (mod p)
// 用于计算 EID = (r × G).x,其中 r = AES-ECB-256(EIK, ts_block) mod n
// 曲线参数(SECP160R1_P/A/B/N/GX/GY)声明在 fmdn.h 中。

// 曲线运算用的点结构
typedef struct {
    mbedtls_mpi x, y;
} secp160_point;

static void secp160_point_init(secp160_point *pt)
{
    mbedtls_mpi_init(&pt->x);
    mbedtls_mpi_init(&pt->y);
}

static void secp160_point_free(secp160_point *pt)
{
    mbedtls_mpi_free(&pt->x);
    mbedtls_mpi_free(&pt->y);
}

// 倍点:R = 2P
static int secp160_double(secp160_point *R, const secp160_point *P,
                           const mbedtls_mpi *p, const mbedtls_mpi *a)
{
    mbedtls_mpi lambda, tmp1, tmp2;
    int ret;

    if (mbedtls_mpi_cmp_int(&P->y, 0) == 0)
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;  // 无穷远点

    mbedtls_mpi_init(&lambda);
    mbedtls_mpi_init(&tmp1);
    mbedtls_mpi_init(&tmp2);

    // lambda = (3*x^2 + a) / (2*y) mod p
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&tmp1, &P->x, &P->x));       // tmp1 = x^2
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tmp1, &tmp1, p));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_int(&tmp1, &tmp1, 3));            // tmp1 = 3*x^2
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&tmp1, &tmp1, a));            // tmp1 = 3*x^2 + a
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tmp1, &tmp1, p));

    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_int(&tmp2, &P->y, 2));            // tmp2 = 2*y
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tmp2, &tmp2, p));
    MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod(&tmp2, &tmp2, p));            // tmp2 = (2*y)^-1

    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&lambda, &tmp1, &tmp2));      // lambda = (3*x^2+a)*(2*y)^-1
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&lambda, &lambda, p));

    // x3 = lambda^2 - 2*x
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&tmp1, &lambda, &lambda));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tmp1, &tmp1, p));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_int(&tmp2, &P->x, 2));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&R->x, &tmp1, &tmp2));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&R->x, &R->x, p));

    // y3 = lambda*(x - x3) - y
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&tmp1, &P->x, &R->x));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&tmp2, &lambda, &tmp1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tmp2, &tmp2, p));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&R->y, &tmp2, &P->y));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&R->y, &R->y, p));

cleanup:
    mbedtls_mpi_free(&lambda);
    mbedtls_mpi_free(&tmp1);
    mbedtls_mpi_free(&tmp2);
    return ret;
}

// 点加:R = P + Q(P != Q)
static int secp160_add(secp160_point *R, const secp160_point *P,
                        const secp160_point *Q, const mbedtls_mpi *p)
{
    mbedtls_mpi lambda, tmp1, tmp2;
    int ret;

    // 若 P == Q 则应改用倍点
    if (mbedtls_mpi_cmp_mpi(&P->x, &Q->x) == 0)
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;

    mbedtls_mpi_init(&lambda);
    mbedtls_mpi_init(&tmp1);
    mbedtls_mpi_init(&tmp2);

    // lambda = (y2 - y1) / (x2 - x1) mod p
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&tmp1, &Q->y, &P->y));       // y2 - y1
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tmp1, &tmp1, p));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&tmp2, &Q->x, &P->x));       // x2 - x1
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tmp2, &tmp2, p));
    MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod(&tmp2, &tmp2, p));            // (x2-x1)^-1
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&lambda, &tmp1, &tmp2));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&lambda, &lambda, p));

    // x3 = lambda^2 - x1 - x2
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&tmp1, &lambda, &lambda));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tmp1, &tmp1, p));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&tmp1, &tmp1, &P->x));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&R->x, &tmp1, &Q->x));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&R->x, &R->x, p));

    // y3 = lambda*(x1 - x3) - y1
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&tmp1, &P->x, &R->x));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&tmp2, &lambda, &tmp1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tmp2, &tmp2, p));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&R->y, &tmp2, &P->y));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&R->y, &R->y, p));

cleanup:
    mbedtls_mpi_free(&lambda);
    mbedtls_mpi_free(&tmp1);
    mbedtls_mpi_free(&tmp2);
    return ret;
}

// 标量乘:R = k × G(double-and-add 算法)
static int secp160_scalar_mult(secp160_point *R, const mbedtls_mpi *k,
                                const secp160_point *G, const mbedtls_mpi *p,
                                const mbedtls_mpi *a)
{
    secp160_point temp;
    int ret = 0;
    int started = 0;
    int nbits = (int)mbedtls_mpi_bitlen(k);

    secp160_point_init(&temp);

    for (int i = nbits - 1; i >= 0; i--)
    {
        if (started)
        {
            // 倍点
            secp160_point temp2;
            secp160_point_init(&temp2);
            ret = secp160_double(&temp2, &temp, p, a);
            if (ret != 0) { secp160_point_free(&temp2); goto cleanup; }
            secp160_point_free(&temp);
            temp = temp2;
        }

        if (mbedtls_mpi_get_bit(k, i) == 1)
        {
            if (!started)
            {
                // 最高位:R = G
                ret = mbedtls_mpi_copy(&temp.x, &G->x);
                if (ret != 0) goto cleanup;
                ret = mbedtls_mpi_copy(&temp.y, &G->y);
                if (ret != 0) goto cleanup;
                started = 1;
            }
            else
            {
                // temp = temp + G
                secp160_point temp2;
                secp160_point_init(&temp2);
                ret = secp160_add(&temp2, &temp, G, p);
                if (ret != 0) { secp160_point_free(&temp2); goto cleanup; }
                secp160_point_free(&temp);
                temp = temp2;
            }
        }
    }

    if (started)
    {
        ret = mbedtls_mpi_copy(&R->x, &temp.x);
        if (ret != 0) goto cleanup;
        ret = mbedtls_mpi_copy(&R->y, &temp.y);
    }
    else
    {
        // k = 0,返回无穷远点(x = 0, y = 1)
        ret = mbedtls_mpi_lset(&R->x, 0);
        if (ret != 0) goto cleanup;
        ret = mbedtls_mpi_lset(&R->y, 1);
    }

cleanup:
    secp160_point_free(&temp);
    return ret;
}

// ============================================================
// EID 生成:EID = (AES-ECB-256(EIK, ts_block) mod n × G).x
// ============================================================

// 为当前时间生成 160 位 EID
// 成功返回 0,并将临时标识符写入 eid[20]
int fmdn_eid_generate(const uint8_t eik[32], uint32_t timestamp,
                      uint8_t eid_out[FMDN_EID_LEN])
{
    int ret;
    uint8_t ts_block[32], r_bytes[32];
    mbedtls_mpi r_prime, n, r, p_mpi, a_mpi;
    secp160_point G, R;

    // 步骤 1:对时间戳做掩码(清除最低 K 位)
    uint32_t masked_ts = timestamp & ~((1u << FMDN_EID_ROTATION_K) - 1);

    // 步骤 2:构造 32 字节数据块(与 GoogleFindMyTools 的 Python 实现一致)
    // 字节 0-10:  0xFF × 11
    // 字节 11:    K = 0x0A
    // 字节 12-15: masked_ts(大端)
    // 字节 16-26: 0x00 × 11
    // 字节 27:    K = 0x0A
    // 字节 28-31: masked_ts(大端)
    memset(ts_block, 0xFF, 11);
    ts_block[11] = FMDN_EID_ROTATION_K;
    ts_block[12] = (uint8_t)(masked_ts >> 24) & 0xFF;
    ts_block[13] = (uint8_t)(masked_ts >> 16) & 0xFF;
    ts_block[14] = (uint8_t)(masked_ts >> 8) & 0xFF;
    ts_block[15] = (uint8_t)(masked_ts & 0xFF);
    memset(&ts_block[16], 0, 11);
    ts_block[27] = FMDN_EID_ROTATION_K;
    ts_block[28] = (uint8_t)(masked_ts >> 24) & 0xFF;
    ts_block[29] = (uint8_t)(masked_ts >> 16) & 0xFF;
    ts_block[30] = (uint8_t)(masked_ts >> 8) & 0xFF;
    ts_block[31] = (uint8_t)(masked_ts & 0xFF);

    // 步骤 3:AES-ECB-256 加密(EIK 作密钥,ts_block 作明文)
    ret = aes_ecb_256_encrypt_block32(eik, ts_block, r_bytes);
    if (ret != 0)
    {
        LOG_E("EID: AES-ECB-256 failed: %d", ret);
        return ret;
    }

    // 步骤 4:r' = bytes_to_bigint_be(r_bytes),再 r = r' mod n
    mbedtls_mpi_init(&r_prime);
    mbedtls_mpi_init(&n);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&p_mpi);
    mbedtls_mpi_init(&a_mpi);

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&r_prime, r_bytes, 32));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&n, 16, SECP160R1_N));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&r, &r_prime, &n));

    // 步骤 5:R = r × G(SECP160R1 上的标量乘)
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&p_mpi, 16, SECP160R1_P));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&a_mpi, 16, SECP160R1_A));

    secp160_point_init(&G);
    secp160_point_init(&R);
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&G.x, 16, SECP160R1_GX));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&G.y, 16, SECP160R1_GY));

    ret = secp160_scalar_mult(&R, &r, &G, &p_mpi, &a_mpi);
    if (ret != 0)
    {
        LOG_E("EID: scalar mult failed: %d", ret);
        goto cleanup;
    }

    // 步骤 6:EID = R.x(20 字节,大端,前导补零)
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&R.x, eid_out, FMDN_EID_LEN));

    LOG_I("EID generated for ts=%u (masked=%u)", timestamp, masked_ts);

cleanup:
    mbedtls_mpi_free(&r_prime);
    mbedtls_mpi_free(&n);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&p_mpi);
    mbedtls_mpi_free(&a_mpi);
    secp160_point_free(&G);
    secp160_point_free(&R);
    return ret;
}

// 获取当前的开机以来秒数(近似值,用于 EID 轮换)
uint32_t fmdn_get_timestamp(void)
{
    app_env_t *env = ble_app_get_env();
    return env->unix_time_offset + (uint32_t)(rt_tick_get() / RT_TICK_PER_SECOND);
}

// ============================================================
// 模块:配网生命周期 & 广播帧刷新(占位 EID / UT 模式 / 反配网)
// ============================================================

// 未配网时广播的占位 EID(全局,供广播刷新复用)
static const uint8_t g_dummy_eid[FMDN_EID_LEN] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13
};

// 当前广播帧应使用的 UT 字节(0x40 UT 关 / 0x41 UT 开)
static uint8_t fmdn_ut_byte(app_env_t *env)
{
    return env->ut_mode ? FMDN_UT_ON : FMDN_UT_OFF;
}

// 用指定 EID + 当前 UT 字节重建并更新广播数据
static void fmdn_adv_set_frame(app_env_t *env, const uint8_t *eid)
{
    sibles_advertising_para_t para = {0};
    uint8_t frame_size = 1 + FMDN_AD_TOTAL_LEN;

    para.adv_data.customized_data = rt_malloc(frame_size);
    if (!para.adv_data.customized_data)
        return;

    fmdn_frame_build(para.adv_data.customized_data->data, fmdn_ut_byte(env), eid);
    para.adv_data.customized_data->len = frame_size;
    sibles_advertising_update_adv_and_scan_rsp_data(g_app_advertising_context,
                                                     &para.adv_data, NULL);
    rt_free(para.adv_data.customized_data);
}

// 按当前状态刷新广播帧(已配网→真实 EID,否则占位 EID;UT 字节随 ut_mode)
// 连接期间所做的 UT/EIK 更改,在断开后通过本函数生效(符合规范"连接断开后生效")
static void fmdn_adv_refresh(app_env_t *env)
{
    fmdn_adv_set_frame(env, env->is_provisioned ? env->current_eid : g_dummy_eid);
}

// 更新 EID 并刷新广播数据(已配网时)
void fmdn_eid_update(void)
{
    app_env_t *env = ble_app_get_env();

    if (!env->is_provisioned)
        return;

    uint32_t ts = fmdn_get_timestamp();
    int ret = fmdn_eid_generate(env->eik, ts, env->current_eid);
    if (ret != 0)
    {
        LOG_E("EID generation failed: %d", ret);
        return;
    }

    LOG_HEX("EID updated", 16, env->current_eid, FMDN_EID_LEN);
    fmdn_adv_set_frame(env, env->current_eid);
    fmdn_store_save_clock(ts);   // 顺便持久化当前时钟(断电恢复用,周期 ~1024s)
}

// 定时器回调:通知主线程去轮换 EID
//(这里不能做重的加密运算 —— 定时器线程栈太小!)
#define FMDN_MSG_EID_ROTATE  0xF0
#define FMDN_MSG_ADV_REFRESH 0xF1   // 断开后刷新广播帧(使连接期间的更改生效)
static void fmdn_eid_timer_cb(void *parameter)
{
    app_env_t *env = ble_app_get_env();
    if (env->mb_handle)
        rt_mb_send(env->mb_handle, FMDN_MSG_EID_ROTATE);
}

// 启动 EID 轮换定时器
void fmdn_eid_timer_start(void)
{
    app_env_t *env = ble_app_get_env();
    // 避免重复创建(例如重新配网时)
    if (env->eid_timer)
        return;
    env->eid_timer = rt_timer_create("fmdn_eid", fmdn_eid_timer_cb, NULL,
                                      rt_tick_from_millisecond(1024000),  // 1024 秒
                                      RT_TIMER_FLAG_PERIODIC | RT_TIMER_FLAG_SOFT_TIMER);
    if (env->eid_timer)
        rt_timer_start(env->eid_timer);
}

// 停止并删除 EID 轮换定时器(反配网时)
static void fmdn_eid_timer_stop(void)
{
    app_env_t *env = ble_app_get_env();
    if (env->eid_timer)
    {
        rt_timer_stop(env->eid_timer);
        rt_timer_delete(env->eid_timer);
        env->eid_timer = NULL;
    }
}

// 反配网(CLEAR_EIK):清密钥、停轮换、清持久化、广播切回占位 EID
static void fmdn_unprovision(app_env_t *env)
{
    fmdn_eid_timer_stop();
    env->is_provisioned = 0;
    env->ut_mode = 0;
    memset(env->eik, 0, sizeof(env->eik));
    memset(env->current_eid, 0, sizeof(env->current_eid));
    fmdn_store_clear();                     // 清除 flash 中的配网记录
    fmdn_adv_set_frame(env, g_dummy_eid);   // 广播切回占位 EID(UT 关)
    LOG_I("Unprovisioned: EIK cleared, advertising dummy EID");
}

// 设置 UT(防恶意追踪)模式:切换广播帧类型 0x40/0x41 并刷新广播
static void fmdn_set_ut_mode(app_env_t *env, bool on)
{
    env->ut_mode = on ? 1 : 0;
    // 用当前 EID(已配网用真实,否则占位)重建广播,UT 字节随之变化
    fmdn_adv_set_frame(env, env->is_provisioned ? env->current_eid : g_dummy_eid);
    LOG_I("UT mode %s (frame type 0x%02X)", on ? "ON" : "OFF", fmdn_ut_byte(env));
}

// ============================================================
// GATT 回调:Beacon Actions(FMDN 挑战-应答)
// ============================================================

// 生成一个简单的 nonce(量产请改用硬件 TRNG)
// nonce 的生成/失效已封装到 fmdn_auth 模块(fmdn_nonce_refresh / fmdn_nonce_consume)

// 读响应缓冲区:[版本(1B) | Nonce(8B)]
static uint8_t g_read_buf[1 + FMDN_NONCE_LEN];  // 9 字节

// 手机读取 Beacon Actions → 返回版本号 + 新生成的 nonce
static uint8_t *fmdn_gatts_get_cbk(uint8_t conn_idx, uint8_t idx, uint16_t *len)
{
    app_env_t *env = ble_app_get_env();
    *len = 0;
    switch (idx)
    {
    case FMDN_BEACON_ACTIONS:
        // 每次读取都生成一个新的一次性 nonce(挑战)
        fmdn_nonce_refresh(&env->gatt.nonce);
        g_read_buf[0] = FMDN_PROTOCOL_VERSION;
        memcpy(&g_read_buf[1], env->gatt.nonce.value, FMDN_NONCE_LEN);
        *len = sizeof(g_read_buf);
        LOG_HEX("Nonce generated", 16, env->gatt.nonce.value, FMDN_NONCE_LEN);
        return g_read_buf;
    default:
        break;
    }
    return NULL;
}

// Notify 响应缓冲区及其辅助函数
static uint8_t g_notify_buf[64];

static void fmdn_notify_response(app_env_t *env, uint8_t data_id, const uint8_t *resp_data, uint8_t resp_len)
{
    if (!env->gatt.is_cccd_on)
    {
        LOG_W("Notifications not enabled, cannot send response");
        return;
    }
    // 构造响应:[DataID(1B)|DataLen(1B)|认证段(8B)|响应数据...]
    // 认证段 = HMAC(本次密钥, version||nonce||id||len||附加数据||0x01)[:8]
    // 依据规范 Table 6;附加数据按"加密后"的字节参与计算(0x00/0x04 已在调用前加密)。
    g_notify_buf[0] = data_id;
    g_notify_buf[1] = resp_len;       // DataLen = 附加数据长度(不含 8B 认证段)
    {
        uint8_t tag[FMDN_AUTH_TAG_LEN];
        if (env->gatt.cur_key_len > 0 &&
            fmdn_auth_compute_resp_tag(env->gatt.cur_key, env->gatt.cur_key_len,
                                       FMDN_PROTOCOL_VERSION, env->gatt.cur_nonce,
                                       data_id, resp_len, resp_data, resp_len, tag) == 0)
            memcpy(&g_notify_buf[2], tag, FMDN_AUTH_TAG_LEN);
        else
            memset(&g_notify_buf[2], 0, FMDN_AUTH_TAG_LEN);
    }
    if (resp_len > 0 && resp_data)
    {
        if (resp_len > sizeof(g_notify_buf) - 10)
            resp_len = sizeof(g_notify_buf) - 10;  // 限制在缓冲区大小内
        memcpy(&g_notify_buf[10], resp_data, resp_len);
    }

    uint16_t total_len = 2 + 8 + resp_len;  // DataID + DataLen + VerifyKey + 响应

    sibles_value_t value;
    value.hdl = env->gatt.srv_handle;
    value.idx = FMDN_BEACON_ACTIONS;
    value.len = total_len;
    value.value = g_notify_buf;

    int ret = sibles_write_value(env->conn_idx, &value);
    LOG_I("Notify DataID=0x%02X, len=%d, ret=%d", data_id, total_len, ret);
}

// 手机写入 Beacon Actions → 解析挑战-应答
static uint8_t fmdn_gatts_set_cbk(uint8_t conn_idx, sibles_set_cbk_t *para)
{
    app_env_t *env = ble_app_get_env();
    switch (para->idx)
    {
    case FMDN_BEACON_ACTIONS:
    {
        // 报文格式:[DataID(1B)|DataLen(1B)|AuthKey(8B)|附加数据...]
        if (para->len < 10)
        {
            LOG_W("Write too short: %d bytes (need >= 10)", para->len);
            return 0x81;  // 非法值
        }

        uint8_t data_id  = para->value[0];
        uint8_t data_len = para->value[1];
        const uint8_t *recv_tag = &para->value[2];     // 8 字节 AuthKey
        const uint8_t *add_data = &para->value[10];    // 附加数据(若有)
        uint32_t add_len = (para->len > 10) ? (uint32_t)(para->len - 10) : 0;

        LOG_HEX("Beacon Actions Write", 16, para->value, para->len);
        LOG_I("  DataID=0x%02X, DataLen=%d", data_id, data_len);

        // --- 挑战-应答认证 ---
        // 先取用一次性 nonce:用过即失效(无论后续成败),旧 nonce 复用会失败
        uint8_t used_nonce[FMDN_NONCE_LEN];
        bool has_nonce = fmdn_nonce_consume(&env->gatt.nonce, used_nonce);

        // 按操作类型选择认证密钥:
        //   0x00-0x03 → Account Key(16B)
        //   0x04      → Recovery Key(8B,EIK 派生)
        //   0x05/0x06 → Ring Key(8B,EIK 派生)
        //   0x07/0x08 → UT Key(8B,EIK 派生)
        const uint8_t *auth_key = NULL;
        uint32_t auth_key_len = 0;
        uint8_t subkey[FMDN_AUTH_TAG_LEN];
        uint8_t subkey_suffix = 0;
        bool need_auth = true;

        switch (data_id)
        {
        case FMDN_DATA_ID_READ_BEACON_PARAMS:
        case FMDN_DATA_ID_READ_PROVISIONING_STATE:
        case FMDN_DATA_ID_SET_EIK:
        case FMDN_DATA_ID_CLEAR_EIK:
            auth_key = env->account_key;
            auth_key_len = 16;
            break;
        case FMDN_DATA_ID_READ_EIK:
            subkey_suffix = FMDN_SUBKEY_RECOVERY;
            break;
        case FMDN_DATA_ID_RING:
        case FMDN_DATA_ID_READ_RING_STATE:
            subkey_suffix = FMDN_SUBKEY_RING;
            break;
        case FMDN_DATA_ID_ENABLE_UT:
        case FMDN_DATA_ID_DISABLE_UT:
            subkey_suffix = FMDN_SUBKEY_UT;
            break;
        default:
            need_auth = false;   // 未知 DataID,留给下面 default 返回 0x81
            break;
        }

        if (need_auth)
        {
            if (!has_nonce)
            {
                LOG_W("Auth fail: no valid nonce (read first / nonce reused) -> 0x80");
                return 0x80;   // 未认证(含旧 nonce 复用)
            }

            // 子密钥类(0x04-0x08)需已配网,否则无 EIK 可派生
            if (subkey_suffix != 0)
            {
                if (!env->is_provisioned)
                {
                    LOG_W("Auth fail: not provisioned, no EIK for subkey -> 0x80");
                    return 0x80;
                }
                if (fmdn_auth_derive_subkey(env->eik, subkey_suffix, subkey) != 0)
                {
                    LOG_E("Auth fail: subkey derive error -> 0x80");
                    return 0x80;
                }
                auth_key = subkey;
                auth_key_len = FMDN_AUTH_TAG_LEN;
            }

            if (!fmdn_auth_verify(auth_key, auth_key_len, FMDN_PROTOCOL_VERSION,
                                  used_nonce, data_id, data_len,
                                  add_data, add_len, recv_tag))
            {
                LOG_W("Auth fail: HMAC mismatch -> 0x80");
                return 0x80;   // 未认证
            }
            LOG_I("Auth OK (DataID=0x%02X)", data_id);

            // 保存本次认证上下文,供响应 notify 计算认证段(同密钥 + 同 nonce)
            rt_memcpy(env->gatt.cur_key, auth_key, auth_key_len);
            env->gatt.cur_key_len = auth_key_len;
            rt_memcpy(env->gatt.cur_nonce, used_nonce, FMDN_NONCE_LEN);
        }

        // 按 Data ID 分发
        switch (data_id)
        {
        case FMDN_DATA_ID_READ_BEACON_PARAMS:
        {
            // 依据规范 Table 6(data ID 0x00):16 字节附加数据,
            // 应用 account key 做 AES-ECB-128 加密(加密推迟到认证那一版,
            // 当前先把字节布局做对)。
            //   [0]    校准发射功率(有符号,0m 处 dBm)
            //   [1-4]  时钟值(uint32,大端,秒)
            //   [5]    曲线选择(0x00 = SECP160R1)
            //   [6]    可响铃组件数(0x01 = 单个)
            //   [7]    响铃能力(0x00 = 无音量选择)
            //   [8-15] 补零(凑满 AES 块)
            uint32_t clock = fmdn_get_timestamp();
            uint8_t resp[16] = {0};
            resp[0] = 0x00;                        // 校准发射功率(占位 0 dBm)
            resp[1] = (uint8_t)(clock >> 24);      // 时钟值(大端)
            resp[2] = (uint8_t)(clock >> 16);
            resp[3] = (uint8_t)(clock >> 8);
            resp[4] = (uint8_t)(clock & 0xFF);
            resp[5] = 0x00;                        // 曲线:SECP160R1
            resp[6] = 0x01;                        // 组件:单个组件可响铃
            resp[7] = 0x00;                        // 响铃能力:无音量选择
            // resp[8..15] 已补零
            // 用 account key 做 AES-ECB-128 加密(规范要求加密后再返回)
            uint8_t enc_params[16];
            if (aes_ecb_128_crypt(env->account_key, resp, enc_params, MBEDTLS_AES_ENCRYPT) != 0)
                return 0x81;
            fmdn_notify_response(env, data_id, enc_params, sizeof(enc_params));
            break;
        }
        case FMDN_DATA_ID_READ_PROVISIONING_STATE:
        {
            // 响应:[状态(1B) | 当前 EID(20B)]
            // 状态:0x00 = 未配网,0x01 = 已配网
            uint8_t resp[21] = {0};
            resp[0] = env->is_provisioned ? 0x01 : 0x00;
            if (env->is_provisioned)
                memcpy(&resp[1], env->current_eid, FMDN_EID_LEN);
            fmdn_notify_response(env, data_id, resp, sizeof(resp));
            LOG_I("Provisioning state: %s", env->is_provisioned ? "PROVISIONED" : "UNPROVISIONED");
            break;
        }
        case FMDN_DATA_ID_SET_EIK:
        {
            LOG_I(">>> SET_EIK received!");
            // 格式:[DataID|DataLen|AuthKey(8B)|加密EIK(32B)] 可选再 +8B 当前 EIK hash
            // DataLen = 0x20(首次配网) 或 0x28(换钥时附带当前 EIK hash)
            if (add_len < 32)
            {
                LOG_W("SET_EIK: data too short! need >=32, got %u", add_len);
                return 0x81;  // 非法值
            }

            // 规范校验(Table 2 / Set EIK):
            //   - 附带当前 EIK hash → 换钥:必须已配网且 hash 匹配当前 EIK
            //   - 未附带 hash       → 首次配网:必须尚未配网
            bool hash_provided = (add_len >= 40);
            if (hash_provided)
            {
                if (!env->is_provisioned)
                {
                    LOG_W("SET_EIK: hash provided but not provisioned -> 0x80");
                    return 0x80;
                }
                const uint8_t *recv_hash = &para->value[10 + 32];  // 加密EIK之后的 8 字节
                if (!fmdn_auth_verify_eik_hash(env->eik, used_nonce, recv_hash))
                {
                    LOG_W("SET_EIK: current EIK hash mismatch -> 0x80");
                    return 0x80;
                }
                LOG_I("SET_EIK: current EIK hash verified (re-key)");
            }
            else if (env->is_provisioned)
            {
                LOG_W("SET_EIK: already provisioned, no EIK hash -> 0x80");
                return 0x80;
            }

            const uint8_t *encrypted_eik = &para->value[10]; // 跳过头部 + 认证段
            int ret = fmdn_decrypt_eik(env->account_key, encrypted_eik, env->eik);

            if (ret == 0)
            {
                env->is_provisioned = 1;
                LOG_HEX("EIK decrypted successfully", 16, env->eik, 32);
                LOG_I("Device is now PROVISIONED!");
                fmdn_store_save(env);      // 持久化:配网状态写入 flash
                fmdn_eid_update();         // 生成第一个 EID
                fmdn_eid_timer_start();    // 启动轮换定时器
                fmdn_notify_response(env, data_id, NULL, 0);
            }
            else
            {
                LOG_E("Failed to decrypt EIK: %d", ret);
                return 0x81;
            }
            break;
        }
        case FMDN_DATA_ID_CLEAR_EIK:
        {
            LOG_I(">>> CLEAR_EIK received!");
            if (!env->is_provisioned)
            {
                LOG_W("CLEAR_EIK: not provisioned -> 0x80");
                return 0x80;   // 未配网,无可清除
            }
            // 规范要求:必须附带并校验当前 EIK hash = SHA256(EIK||nonce)[:8]
            if (add_len < 8)
            {
                LOG_W("CLEAR_EIK: missing EIK hash -> 0x81");
                return 0x81;
            }
            if (!fmdn_auth_verify_eik_hash(env->eik, used_nonce, add_data))
            {
                LOG_W("CLEAR_EIK: EIK hash mismatch -> 0x80");
                return 0x80;
            }
            LOG_I("CLEAR_EIK: EIK hash verified");
            fmdn_unprovision(env);   // 清密钥 + 停轮换 + 清 flash + 广播切占位
            fmdn_notify_response(env, data_id, NULL, 0);
            break;
        }
        case FMDN_DATA_ID_READ_EIK:
        {
            LOG_I(">>> READ_EIK received!");
            if (!env->is_provisioned)
            {
                LOG_W("READ_EIK: not provisioned -> 0x80");
                return 0x80;
            }
            if (!env->pairing_mode)
            {
                LOG_W("READ_EIK: not in pairing mode -> 0x82");
                return 0x82;   // 无用户同意(需进入配对模式)
            }
            // 返回用 account key 加密的 EIK(32B = 2 个 AES 块)
            uint8_t enc_eik[32];
            if (aes_ecb_128_crypt(env->account_key, &env->eik[0],  &enc_eik[0],  MBEDTLS_AES_ENCRYPT) != 0 ||
                aes_ecb_128_crypt(env->account_key, &env->eik[16], &enc_eik[16], MBEDTLS_AES_ENCRYPT) != 0)
                return 0x81;
            fmdn_notify_response(env, data_id, enc_eik, sizeof(enc_eik));
            break;
        }
        case FMDN_DATA_ID_RING:
        {
            LOG_I(">>> RING! (play sound here)");
            // 依据规范 Table 6(data ID 0x05):响铃状态变化通知
            //   [0]   响铃状态(0x00 = 已开始)
            //   [1]   正在响铃的组件位掩码(0x01 = 单个组件)
            //   [2-3] 剩余超时,单位分秒(大端)
            uint8_t resp[] = {0x00, 0x01, 0x00, 0x00}; // 已开始,单个组件
            fmdn_notify_response(env, data_id, resp, sizeof(resp));
            break;
        }
        case FMDN_DATA_ID_READ_RING_STATE:
        {
            uint8_t resp[] = {0x00, 0x00, 0x00}; // 未在响铃
            fmdn_notify_response(env, data_id, resp, sizeof(resp));
            break;
        }
        case FMDN_DATA_ID_ENABLE_UT:
        {
            LOG_I(">>> Enable Unwanted Tracking mode");
            fmdn_set_ut_mode(env, true);    // 广播帧类型切 0x41
            fmdn_notify_response(env, data_id, NULL, 0);
            break;
        }
        case FMDN_DATA_ID_DISABLE_UT:
        {
            LOG_I(">>> Disable Unwanted Tracking mode");
            // 规范(Table 5):附带并校验 EIK hash = SHA256(EIK||nonce)[:8]
            if (add_len < 8)
            {
                LOG_W("Disable UT: missing EIK hash -> 0x81");
                return 0x81;
            }
            if (!fmdn_auth_verify_eik_hash(env->eik, used_nonce, add_data))
            {
                LOG_W("Disable UT: EIK hash mismatch -> 0x80");
                return 0x80;
            }
            LOG_I("Disable UT: EIK hash verified");
            fmdn_set_ut_mode(env, false);   // 广播帧类型切回 0x40
            fmdn_notify_response(env, data_id, NULL, 0);
            break;
        }
        default:
            LOG_W("Unknown DataID: 0x%02X", data_id);
            return 0x81;  // 非法值
        }
        return 0;  // 成功
    }
    case FMDN_CCCD:
    {
        env->gatt.is_cccd_on = *(para->value);
        LOG_I("Notifications: %s", env->gatt.is_cccd_on ? "ON" : "OFF");
        break;
    }
    default:
        break;
    }
    return 0;
}

// 注册 Fast Pair GATT 服务
static void fmdn_gatt_service_init(void)
{
    app_env_t *env = ble_app_get_env();
    BLE_GATT_SERVICE_INIT_128(svc, fmdn_att_db, FMDN_ATT_NB,
                              BLE_GATT_SERVICE_PERM_NOAUTH | BLE_GATT_SERVICE_PERM_UUID_128 |
                              BLE_GATT_SERVICE_PERM_MULTI_LINK,
                              g_fp_service_uuid);

    env->gatt.srv_handle = sibles_register_svc_128(&svc);
    if (env->gatt.srv_handle)
        sibles_register_cbk(env->gatt.srv_handle, fmdn_gatts_get_cbk, fmdn_gatts_set_cbk);
    else
        LOG_E("GATT service registration failed!");
}


/* 通过广播服务启用广播。 */
// ============================================================
// 模块:BLE 广播启动 / 连接管理
// ============================================================
static void ble_app_ibeacon_advertising_start(void)
{
    sibles_advertising_para_t para = {0};
    uint8_t ret;
    app_env_t *env = ble_app_get_env();

    bd_addr_t addr;
    ret = ble_get_public_address(&addr);
    if (ret == HL_ERR_NO_ERROR)
    {
        LOG_I("ble_get_public_address :%02x-%02x-%02x-%02x-%02x-%02x", addr.addr[5], addr.addr[4], addr.addr[3], addr.addr[2], addr.addr[1], addr.addr[0]);
    }
    else
    {
        LOG_I("ble_get_public_address ERROR");
    }


    // --- 设置设备名,便于手机识别 ---
    char local_name[] = "FMDN_Tag";
    ble_gap_dev_name_t *dev_name = rt_malloc(sizeof(ble_gap_dev_name_t) + strlen(local_name));
    dev_name->len = strlen(local_name);
    memcpy(dev_name->name, local_name, dev_name->len);
    ble_gap_set_dev_name(dev_name);
    rt_free(dev_name);

    para.own_addr_type = GAPM_STATIC_ADDR;
    // CONNECT_MODE = 允许手机连接本设备
    para.config.adv_mode = SIBLES_ADV_CONNECT_MODE;

    para.config.mode_config.conn_config.duration = 0;    // 0 = 不限时
    para.config.mode_config.conn_config.interval = 0x30;  // 约 60ms

    // 断开后自动重启广播
    para.config.is_auto_restart = 1;

    para.config.max_tx_pwr = 0x7F;

    // --- FMDN:用真实 EID 构造广播帧 ---
    const uint8_t *eid_to_use;

    if (env->is_provisioned)
    {
        // 生成第一个真实 EID
        fmdn_eid_generate(env->eik, fmdn_get_timestamp(), env->current_eid);
        eid_to_use = env->current_eid;
        LOG_I("Using real EID (provisioned)");
    }
    else
    {
        eid_to_use = g_dummy_eid;   // 复用全局占位 EID
        LOG_I("Using dummy EID (not provisioned)");
    }

    uint8_t frame_size = 1 + FMDN_AD_TOTAL_LEN;  // 1(长度字节) + 24 = 25 字节

    para.adv_data.customized_data = rt_malloc(frame_size);
    fmdn_frame_build(para.adv_data.customized_data->data, fmdn_ut_byte(env), eid_to_use);
    para.adv_data.customized_data->len = frame_size;



    para.evt_handler = ble_app_advertising_event;


    ret = sibles_advertising_init(g_app_advertising_context, &para);
    LOG_I("sibles_advertising_init called");
    if (ret == SIBLES_ADV_NO_ERR)
    {
        sibles_advertising_start(g_app_advertising_context);
        LOG_I("sibles_advertising_start called");
    }


    rt_free(para.adv_data.customized_data);

}

// ============================================================
// 模块:主循环 & BLE 事件处理
//   - main(): 使能 BLE,处理上电(注册 GATT + 启动广播)
//     以及来自定时器线程的 EID 轮换消息。
//   - ble_app_event_handler(): BLE 协议栈事件回调
//     (连接 / 断开 / MTU / 广播确认)。
// ============================================================
int main(void)
{
    int count = 0;
    app_env_t *env = ble_app_get_env();
    env->mb_handle = rt_mb_create("app", 8, RT_IPC_FLAG_FIFO);

    // 初始化硬件 TRNG(nonce 随机源);失败则内部回退 rand()
    fmdn_rng_init();

    // 从 flash 恢复配网状态(若有);文件系统已由 board.c 的 mnt_init 挂载
    if (fmdn_store_load(env) == 0 && env->is_provisioned)
    {
        LOG_I("Restored provisioned state from flash");
        fmdn_eid_timer_start();    // 已配网,启动 EID 轮换定时器
    }

    // 断电时钟恢复:用上次保存的 Unix 时钟初始化时间偏移
    uint32_t saved_clock;
    if (fmdn_store_load_clock(&saved_clock) == 0)
    {
        uint32_t boot_sec = (uint32_t)(rt_tick_get() / RT_TICK_PER_SECOND);
        env->unix_time_offset = saved_clock - boot_sec;
        LOG_I("Clock restored from flash: %u", saved_clock);
    }

    sifli_ble_enable();

    while (1)
    {
        uint32_t value;
        int ret;
        rt_mb_recv(env->mb_handle, (rt_uint32_t *)&value, RT_WAITING_FOREVER);
        if (value == BLE_POWER_ON_IND)
        {
            env->is_power_on = 1;

            // 广播前先注册 GATT 服务
            fmdn_gatt_service_init();

            // 用 FMDN 帧启动广播
            ble_app_ibeacon_advertising_start();
            LOG_I("receive BLE power on!\r\n");
        }
        else if (value == FMDN_MSG_EID_ROTATE)
        {
            // EID 轮换:重的加密运算放在主线程做,不在定时器线程
            fmdn_eid_update();
        }
        else if (value == FMDN_MSG_ADV_REFRESH)
        {
            // 断开后自动重启广播需要一点时间到达 STARTED 状态;
            // update_adv 仅在 STARTED 时生效,故先等一下再刷新,
            // 使连接期间的 UT/EIK 更改真正写入广播。
            rt_thread_mdelay(200);
            fmdn_adv_refresh(env);
            LOG_I("ADV refreshed (ut_mode=%d, provisioned=%d)", env->ut_mode, env->is_provisioned);
        }
    }
    return RT_EOK;
}

int ble_app_event_handler(uint16_t event_id, uint8_t *data, uint16_t len, uint32_t context)
{
    app_env_t *env = ble_app_get_env();
    switch (event_id)
    {
    case BLE_POWER_ON_IND:
    {
        /* 放到自己的线程里处理,避免冲突 */
        if (env->mb_handle)
            rt_mb_send(env->mb_handle, BLE_POWER_ON_IND);
        break;
    }
    case BLE_GAP_CONNECTED_IND:
    {
        ble_gap_connect_ind_t *ind = (ble_gap_connect_ind_t *)data;
        env->conn_idx = ind->conn_idx;
        LOG_I("Phone connected! addr=%02x:%02x:%02x:%02x:%02x:%02x, interval=%d",
              ind->peer_addr.addr[5], ind->peer_addr.addr[4],
              ind->peer_addr.addr[3], ind->peer_addr.addr[2],
              ind->peer_addr.addr[1], ind->peer_addr.addr[0],
              ind->con_interval);
        // 设备侧主动发起 MTU 协商,确保通知 >20 字节不被默认 MTU(23)截断,
        // 不再依赖手机端手动 Request MTU。
        sibles_exchange_mtu(ind->conn_idx);
        break;
    }
    case BLE_GAP_DISCONNECTED_IND:
    {
        ble_gap_disconnected_ind_t *ind = (ble_gap_disconnected_ind_t *)data;
        LOG_I("Phone disconnected, reason=%d", ind->reason);
        // 连接期间的 UT/EIK 更改在此刷新到广播(交主线程,在自动重启广播之后执行)
        if (env->mb_handle)
            rt_mb_send(env->mb_handle, FMDN_MSG_ADV_REFRESH);
        break;
    }
    case SIBLES_MTU_EXCHANGE_IND:
    {
        sibles_mtu_exchange_ind_t *ind = (sibles_mtu_exchange_ind_t *)data;
        LOG_I("MTU negotiated: %d", ind->mtu);
        break;
    }
    case BLE_GAP_SET_ADV_DATA_CNF:
    {
        ble_gap_set_adv_data_cnf_t *cnf = (ble_gap_set_adv_data_cnf_t *)data;
        LOG_I("Set ADV_DATA result %d", cnf->status);
        break;
    }
    case BLE_GAP_START_ADV_CNF:
    {
        ble_gap_start_adv_cnf_t *cnf = (ble_gap_start_adv_cnf_t *)data;
        LOG_I("Start ADV result %d", cnf->status);
        break;
    }
    default:
        break;
    }
    return 0;
}
BLE_EVENT_REGISTER(ble_app_event_handler, NULL);

// ============================================================
// 模块:广播控制包装函数(导出给测试命令使用)
// ============================================================
void ble_app_adv_start(void)
{
    sibles_advertising_start(g_app_advertising_context);
}

void ble_app_adv_stop(void)
{
    sibles_advertising_stop(g_app_advertising_context);
}

// ============================================================
// 说明:所有串口测试/调试命令(cmd_diss、cmd_fmdn_*)
//       已移至 fmdn_test_cmds.c。
// ============================================================


#ifdef SF32LB52X_58
// ============================================================
// 模块:LCPU ROM 配置(SF32LB52X 仿真构建)
// ============================================================
uint16_t g_em_offset[HAL_LCPU_CONFIG_EM_BUF_MAX_NUM] =
{
    0x178, 0x178, 0x740, 0x7A0, 0x810, 0x880, 0xA00, 0xBB0, 0xD48,
    0x133C, 0x13A4, 0x19BC, 0x21BC, 0x21BC, 0x21BC, 0x21BC, 0x21BC, 0x21BC,
    0x21BC, 0x21BC, 0x263C, 0x265C, 0x2734, 0x2784, 0x28D4, 0x28E8, 0x28FC,
    0x29EC, 0x29FC, 0x2BBC, 0x2BD8, 0x3BE8, 0x5804, 0x5804, 0x5804
};

void lcpu_rom_config(void)
{
    hal_lcpu_bluetooth_em_config_t em_offset;
    memcpy((void *)em_offset.em_buf, (void *)g_em_offset, HAL_LCPU_CONFIG_EM_BUF_MAX_NUM * 2);
    em_offset.is_valid = 1;
    HAL_LCPU_CONFIG_set(HAL_LCPU_CONFIG_BT_EM_BUF, &em_offset, sizeof(hal_lcpu_bluetooth_em_config_t));

    hal_lcpu_bluetooth_act_configt_t act_cfg;
    act_cfg.ble_max_act = 6;
    act_cfg.ble_max_iso = 0;
    act_cfg.ble_max_ral = 3;
    act_cfg.bt_max_acl = 7;
    act_cfg.bt_max_sco = 0;
    act_cfg.bit_valid = CO_BIT(0) | CO_BIT(1) | CO_BIT(2) | CO_BIT(3) | CO_BIT(4);
    HAL_LCPU_CONFIG_set(HAL_LCPU_CONFIG_BT_ACT_CFG, &act_cfg, sizeof(hal_lcpu_bluetooth_act_configt_t));
}
#endif

