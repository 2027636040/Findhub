/*
 * SPDX-FileCopyrightText: 2024-2024 SiFli Technologies(Nanjing) Co., Ltd
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * fmdn_rng.h —— FMDN 硬件随机数(TRNG)封装。
 *
 * FMDN 的一次性 nonce、以及后续地址隐私(RPA 轮换抖动)都要求使用
 * 密码学强度的随机源。本模块封装芯片硬件 TRNG(bf0_hal_rng),
 * 对外只暴露"初始化"和"填充随机字节"两个接口,屏蔽底层细节。
 *
 * 若硬件 TRNG 不可用(编译未使能或初始化失败),fmdn_rng_fill 会
 * 自动回退到 rand() 以保证功能不中断,但会返回非 0 以示降级。
 */

#ifndef FMDN_RNG_H
#define FMDN_RNG_H

#include <rtthread.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 初始化硬件 TRNG(上电时调用一次)。
 * 返回 0 成功;非 0 表示 TRNG 不可用,后续将走 rand() 兜底。
 */
int fmdn_rng_init(void);

/*
 * 用随机数据填充 buf 的前 len 字节。
 * 返回 0 表示使用了硬件 TRNG;非 0 表示降级到了 rand()(数据仍可用)。
 */
int fmdn_rng_fill(uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* FMDN_RNG_H */
