/*
 * SPDX-FileCopyrightText: 2024-2024 SiFli Technologies(Nanjing) Co., Ltd
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * fmdn_flags.h —— FMDN 广播帧 "Hashed Flags" 字节计算。
 *
 * 规范(FHN v1.3 "Hashed flags"):该字节(bit 自 MSB 向 LSB 编号)
 *   - bit 0-4:保留(置 0)
 *   - bit 5-6:电量等级(00=不支持 / 01=正常 / 10=低 / 11=极低)
 *   - bit 7  :防恶意追踪(UT)模式,1=开启
 * 明文字节再与 SHA256(r) 的最低有效字节异或,得到最终 Hashed Flags。
 * 其中 r 为 EID 计算中的伪随机数,对齐到曲线大小(SECP160R1 = 20 字节)。
 *
 * 注:r 即 EID 计算中的标量 r = r' mod n(见规范 EID computation 章节:
 * 「r' is now projected to Fp by calculating r = r' mod n」),对齐到曲线大小
 * 160 位 = 20 字节大端。固件由 fmdn_eid_generate 的 r_out 提供该值。
 */

#ifndef FMDN_FLAGS_H
#define FMDN_FLAGS_H

#include <rtthread.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 电量等级(对应规范 bit 5-6) */
typedef enum
{
    FMDN_BATT_UNSUPPORTED = 0,   /* 不支持电量指示 */
    FMDN_BATT_NORMAL      = 1,   /* 正常           */
    FMDN_BATT_LOW         = 2,   /* 低             */
    FMDN_BATT_CRITICAL    = 3,   /* 极低(需尽快换电池) */
} fmdn_batt_level_t;

/*
 * 计算 Hashed Flags 字节。
 *   r        : EID 伪随机数(大端),长度 r_len(本项目为 20)
 *   ut_mode  : 是否处于 UT 模式
 *   batt     : 电量等级(本板不支持电量,传 FMDN_BATT_UNSUPPORTED)
 *   out_byte : 输出最终 Hashed Flags 字节
 * 返回 0 成功。
 */
int fmdn_hashed_flags(const uint8_t *r, uint32_t r_len,
                      bool ut_mode, fmdn_batt_level_t batt,
                      uint8_t *out_byte);

#ifdef __cplusplus
}
#endif

#endif /* FMDN_FLAGS_H */
