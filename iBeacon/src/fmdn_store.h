/*
 * SPDX-FileCopyrightText: 2024-2024 SiFli Technologies(Nanjing) Co., Ltd
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * fmdn_store.h —— FMDN 配网状态持久化模块。
 *
 * 把 Account Key / EIK / 配网标志保存到文件系统(板上 NAND,挂载于 "/"),
 * 设备复位后自动恢复,避免每次重启都要重新配网。
 *
 * 接口对调用者隐藏存储介质细节(底层用 POSIX 文件 + 校验和)。
 */

#ifndef FMDN_STORE_H
#define FMDN_STORE_H

#include "fmdn.h"   /* app_env_t */

#ifdef __cplusplus
extern "C" {
#endif

/* 把当前配网状态(AK / EIK / is_provisioned)写入 flash。成功返回 0。 */
int fmdn_store_save(const app_env_t *env);

/*
 * 从 flash 读取配网状态填入 env。
 * 成功返回 0(env 已恢复);无有效记录 / 校验失败返回非 0(env 不变)。
 */
int fmdn_store_load(app_env_t *env);

/* 清除 flash 中的配网记录(出厂复位 / CLEAR_EIK 时调用)。成功返回 0。 */
int fmdn_store_clear(void);

/* 保存当前时钟(Unix 秒)到 flash,用于断电恢复。成功返回 0。 */
int fmdn_store_save_clock(uint32_t unix_time);

/* 读取上次保存的时钟(Unix 秒)。成功返回 0 并填入 *unix_time;无记录返回非 0。 */
int fmdn_store_load_clock(uint32_t *unix_time);

#ifdef __cplusplus
}
#endif

#endif /* FMDN_STORE_H */
