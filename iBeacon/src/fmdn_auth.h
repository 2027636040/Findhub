/*
 * SPDX-FileCopyrightText: 2024-2024 SiFli Technologies(Nanjing) Co., Ltd
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * fmdn_auth.h —— FMDN 挑战-应答认证模块。
 *
 * 封装三块能力,供 GATT 层调用:
 *   1) HMAC-SHA256 计算                (fmdn_hmac_sha256)
 *   2) AuthKey 计算 / 校验             (fmdn_auth_compute_tag / fmdn_auth_verify)
 *   3) 一次性 nonce 生命周期管理        (fmdn_nonce_refresh / fmdn_nonce_consume)
 *
 * 规范(Find Hub v1.3, Tables 2-5):
 *   AuthKey = HMAC-SHA256(key,
 *                 协议版本号 || 上次读取的 nonce || DataID || DataLen || 附加数据)
 *             取前 8 字节
 */

#ifndef FMDN_AUTH_H
#define FMDN_AUTH_H

#include <rtthread.h>
#include <stdbool.h>
#include "fmdn.h"   /* FMDN_NONCE_LEN / FMDN_AUTH_TAG_LEN / fmdn_nonce_t */

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- 子密钥派生 ---------- */

/* 子密钥后缀(规范:SHA256(EIK || suffix) 取前 8 字节) */
#define FMDN_SUBKEY_RECOVERY  0x01   /* Recovery Key:恢复 EIK    */
#define FMDN_SUBKEY_RING      0x02   /* Ring Key:响铃            */
#define FMDN_SUBKEY_UT        0x03   /* UT Key:防恶意追踪        */

/*
 * 从 EIK 派生子密钥:out = SHA256(eik[32] || suffix)[:8]
 * suffix 取 FMDN_SUBKEY_* 之一。返回 0 成功。
 */
int fmdn_auth_derive_subkey(const uint8_t eik[32], uint8_t suffix,
                            uint8_t out[FMDN_AUTH_TAG_LEN]);

/* ---------- EIK hash(证明掌握当前 EIK) ---------- */

/*
 * 计算 EIK hash:out = SHA256(eik[32] || nonce[8])[:8]。
 * 用于 SET_EIK(换钥)/ CLEAR_EIK / 关闭 UT 的附加数据校验。返回 0 成功。
 */
int fmdn_auth_eik_hash(const uint8_t eik[32],
                       const uint8_t nonce[FMDN_NONCE_LEN],
                       uint8_t out[FMDN_AUTH_TAG_LEN]);

/*
 * 校验对方提供的 EIK hash 是否与当前 EIK 匹配(常量时间比较)。
 * 返回 true = 匹配(证明对方掌握当前 EIK)。
 */
bool fmdn_auth_verify_eik_hash(const uint8_t eik[32],
                               const uint8_t nonce[FMDN_NONCE_LEN],
                               const uint8_t recv_hash[FMDN_AUTH_TAG_LEN]);

/* ---------- HMAC ---------- */

/*
 * 计算 HMAC-SHA256,输出完整 32 字节。
 * 返回 0 成功,非 0 为 mbedTLS 错误码。
 */
int fmdn_hmac_sha256(const uint8_t *key, uint32_t key_len,
                     const uint8_t *msg, uint32_t msg_len,
                     uint8_t out[32]);

/* ---------- AuthKey 计算 / 校验 ---------- */

/*
 * 按规范拼接消息并计算 AuthKey(前 FMDN_AUTH_TAG_LEN 字节)。
 *   消息 = version || nonce(8) || data_id || data_len || add_data[add_data_len]
 * add_data 可为 NULL(add_data_len = 0)。
 * 返回 0 成功。
 */
int fmdn_auth_compute_tag(const uint8_t *key, uint32_t key_len,
                          uint8_t protocol_version,
                          const uint8_t nonce[FMDN_NONCE_LEN],
                          uint8_t data_id, uint8_t data_len,
                          const uint8_t *add_data, uint32_t add_data_len,
                          uint8_t tag_out[FMDN_AUTH_TAG_LEN]);

/*
 * 校验收到的 AuthKey 是否匹配(常量时间比较,防时序侧信道)。
 * 参数同 fmdn_auth_compute_tag,recv_tag 为手机写入的 8 字节认证段。
 * 返回 true = 认证通过。
 */
bool fmdn_auth_verify(const uint8_t *key, uint32_t key_len,
                      uint8_t protocol_version,
                      const uint8_t nonce[FMDN_NONCE_LEN],
                      uint8_t data_id, uint8_t data_len,
                      const uint8_t *add_data, uint32_t add_data_len,
                      const uint8_t recv_tag[FMDN_AUTH_TAG_LEN]);

/*
 * 计算响应(notify)认证段:
 *   HMAC-SHA256(key, version || nonce || data_id || data_len || add_data || 0x01)[:8]
 * 与请求认证的区别是消息尾部多一个 0x01(规范 Table 6 各响应的认证段定义)。
 * 返回 0 成功。
 */
int fmdn_auth_compute_resp_tag(const uint8_t *key, uint32_t key_len,
                               uint8_t protocol_version,
                               const uint8_t nonce[FMDN_NONCE_LEN],
                               uint8_t data_id, uint8_t data_len,
                               const uint8_t *add_data, uint32_t add_data_len,
                               uint8_t tag_out[FMDN_AUTH_TAG_LEN]);

/* ---------- 一次性 nonce 生命周期 ---------- */

/* 生成一个新的随机 nonce 并置为有效(每次手机 Read 时调用)。 */
void fmdn_nonce_refresh(fmdn_nonce_t *n);

/*
 * 取用 nonce:若当前有效,则立即失效并返回 true(同时通过 out 带出本次 nonce 值);
 * 若已无效(未读取过 / 已被用过),返回 false。
 * 规范要求 nonce 用过一次即失效,无论后续操作成功与否。
 */
bool fmdn_nonce_consume(fmdn_nonce_t *n, uint8_t out[FMDN_NONCE_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* FMDN_AUTH_H */
