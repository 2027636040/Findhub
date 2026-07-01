/*
 * SPDX-FileCopyrightText: 2024-2024 SiFli Technologies(Nanjing) Co., Ltd
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * fmdn.h —— FMDN 核心(main.c)与串口测试/调试命令(fmdn_test_cmds.c)
 *          之间的共享接口。
 *
 * 这里只导出测试命令需要用到的符号。GATT 服务表、广播帧构造、
 * 挑战-应答回调等仍保留在 main.c 内部(static)。
 */

#ifndef FMDN_H
#define FMDN_H

#include <rtthread.h>
#include <stdbool.h>
#include "bf0_sibles.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- FMDN 常量 ---------- */
#define FMDN_NONCE_LEN          8     /* 挑战 nonce 长度              */
#define FMDN_EID_LEN            20    /* SECP160R1 -> 20 字节 EID     */
#define FMDN_EID_ROTATION_K     10    /* 2^10 = 1024 秒 EID 轮换周期  */
#define FMDN_PROTOCOL_VERSION   0x01  /* 协议主版本号                 */
#define FMDN_AUTH_TAG_LEN       8     /* 截断后的 AuthKey/认证段长度  */

/* ---------- FMDN 操作 Data ID ---------- */
#define FMDN_DATA_ID_READ_BEACON_PARAMS       0x00
#define FMDN_DATA_ID_READ_PROVISIONING_STATE  0x01
#define FMDN_DATA_ID_SET_EIK                  0x02
#define FMDN_DATA_ID_CLEAR_EIK                0x03
#define FMDN_DATA_ID_READ_EIK                 0x04
#define FMDN_DATA_ID_RING                     0x05
#define FMDN_DATA_ID_READ_RING_STATE          0x06
#define FMDN_DATA_ID_ENABLE_UT                0x07
#define FMDN_DATA_ID_DISABLE_UT               0x08

/* ---------- 一次性挑战 nonce(挑战-应答用) ---------- */
typedef struct
{
    uint8_t value[FMDN_NONCE_LEN];
    bool    valid;                     /* 是否有效(一次性,用过即失效) */
} fmdn_nonce_t;

/* ---------- SECP160R1 曲线参数(十六进制,大端) ---------- */
#define SECP160R1_P  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF"
#define SECP160R1_A  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC"
#define SECP160R1_B  "1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45"
#define SECP160R1_N  "0100000000000000000001F4C8F927AED3CA752257"
#define SECP160R1_GX "4A96B5688EF573284664698968C38BB913CBFC82"
#define SECP160R1_GY "23A628553168947D59DCC912042351377AC5FB32"

/* ---------- 应用环境(共享状态) ---------- */
typedef struct
{
    uint8_t is_power_on;
    uint8_t conn_idx;
    rt_mailbox_t mb_handle;

    /* GATT / Beacon Actions 状态 */
    struct
    {
        sibles_hdl srv_handle;
        uint8_t is_cccd_on;            /* 通知是否已开启?            */
        fmdn_nonce_t nonce;            /* 当前一次性挑战 nonce        */
        /* 本次写操作的认证上下文(供响应 notify 计算认证段复用) */
        uint8_t cur_key[16];           /* 认证密钥(account 16B 或子密钥 8B) */
        uint8_t cur_key_len;           /* 密钥长度                    */
        uint8_t cur_nonce[FMDN_NONCE_LEN]; /* 本次使用的 nonce        */
    } gatt;

    /* FMDN 密钥与 EID */
    uint8_t account_key[16];           /* Account Key(来自手机 App) */
    uint8_t owner_account_key[16];     /* Owner Account Key(首次访问 Beacon Actions 时锁定) */
    uint8_t has_owner_key;             /* 是否已锁定 owner account key */
    uint8_t has_account_key;           /* 是否已下发 account key(用于 5 分钟未配网保护) */
    uint8_t eik[32];                   /* 临时身份密钥 EIK(32 字节)  */
    uint8_t is_provisioned;            /* 0 = 未配网,1 = 已设 EIK    */
    uint8_t ut_mode;                   /* 防恶意追踪模式:0=关,1=开  */
    uint8_t pairing_mode;              /* 配对模式:0=关,1=开(0x04 READ_EIK 需要) */
    uint8_t current_eid[FMDN_EID_LEN]; /* 当前临时标识 EID(20 字节)  */
    uint8_t current_r[FMDN_EID_LEN];   /* 当前 EID 对应的标量 r(Hashed Flags 用,20B 大端) */
    rt_timer_t eid_timer;              /* EID 轮换定时器(1024 秒)    */
    rt_timer_t provision_timer;        /* 配网保护定时器(下发 AK 后 5 分钟未配网则工厂复位) */
    uint32_t unix_time_offset;         /* 开机秒数 -> Unix 时间的偏移 */
} app_env_t;

/* ---------- 导出给测试命令的核心访问接口 / 服务 ---------- */

/* 全局应用环境。 */
app_env_t *ble_app_get_env(void);

/* AES-ECB 辅助函数(mbedTLS)。mode = MBEDTLS_AES_ENCRYPT / MBEDTLS_AES_DECRYPT。 */
int aes_ecb_128_crypt(const uint8_t key[16], const uint8_t input[16],
                      uint8_t output[16], int mode);
int aes_ecb_256_encrypt_block32(const uint8_t key_256[32], const uint8_t plain[32],
                                uint8_t cipher[32]);

/* EID 生成引擎。
 * r_out 可选(传 NULL 则忽略):输出 EID 对应的标量 r(20 字节大端),
 * 供 Hashed Flags 计算使用。 */
int fmdn_eid_generate(const uint8_t eik[32], uint32_t timestamp,
                      uint8_t eid_out[FMDN_EID_LEN],
                      uint8_t r_out[FMDN_EID_LEN]);
uint32_t fmdn_get_timestamp(void);
void fmdn_eid_update(void);
void fmdn_eid_timer_start(void);

/* 广播控制包装函数(隐藏广播上下文全局变量)。 */
void ble_app_adv_start(void);
void ble_app_adv_stop(void);

/* 下发 account key 后调用:置位标志并启动 5 分钟未配网保护定时器。 */
void fmdn_account_key_provisioned(void);

/* 供测试命令调用:立即执行一次完整工厂复位(清 account key + EIK)。 */
void fmdn_factory_reset_now(void);

#ifdef __cplusplus
}
#endif

#endif /* FMDN_H */
