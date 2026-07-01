/*
 * SPDX-FileCopyrightText: 2024-2024 SiFli Technologies(Nanjing) Co., Ltd
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * fmdn_flags.c —— FMDN 广播帧 "Hashed Flags" 字节计算实现。
 * 详见 fmdn_flags.h。
 *
 * ┌─────────────────────────────────────────────────────────────┐
 * │ r 取值(已按规范确认)                                        │
 * │   规范 EID computation 章节明确:r' 为 AES-ECB-256 的 256 位  │
 * │   输出,r = r' mod n 为投影到 Fp 的标量,R = r*G,EID = R.x。 │
 * │   Hashed Flags 章节的 SHA256(r) 即用该标量 r,"对齐曲线大小   │
 * │   160 位" = 20 字节大端(不足补零,超出截断高位)。           │
 * │   固件由 fmdn_eid_generate 的 r_out 提供已对齐的 20 字节 r。  │
 * └─────────────────────────────────────────────────────────────┘
 */

#include <rtthread.h>
#include <string.h>

#include "mbedtls/md.h"

#include "fmdn_flags.h"

#define LOG_TAG "fmdn_flags"
#include "log.h"

/* 明文 Hashed Flags 字节(异或前)。
 * 位布局(常规 bit0=LSB):
 *   bit0      = UT 模式(规范 MSB 编号的 bit7)
 *   bit1-2    = 电量等级(规范 MSB 编号的 bit5-6)
 *   bit3-7    = 保留 0
 */
static uint8_t fmdn_flags_plain(bool ut_mode, fmdn_batt_level_t batt)
{
    uint8_t b = 0;
    b |= (uint8_t)((batt & 0x03) << 1);   /* 电量等级 */
    b |= ut_mode ? 0x01 : 0x00;           /* UT 位     */
    return b;
}

int fmdn_hashed_flags(const uint8_t *r, uint32_t r_len,
                      bool ut_mode, fmdn_batt_level_t batt,
                      uint8_t *out_byte)
{
    const mbedtls_md_info_t *info;
    uint8_t hash[32];
    int ret;

    if (r == NULL || r_len == 0 || out_byte == NULL)
        return -1;

    info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (info == NULL)
    {
        LOG_E("SHA256 md_info not available");
        return -1;
    }

    /* SHA256(r):r 为对齐曲线大小的伪随机数(大端) */
    ret = mbedtls_md(info, r, r_len, hash);
    if (ret != 0)
    {
        LOG_E("SHA256 failed: %d", ret);
        return ret;
    }

    /* 明文字节 ^ SHA256(r) 的最低有效字节 */
    *out_byte = fmdn_flags_plain(ut_mode, batt) ^ hash[31];
    return 0;
}
