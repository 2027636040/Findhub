/*
 * SPDX-FileCopyrightText: 2024-2024 SiFli Technologies(Nanjing) Co., Ltd
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * fmdn_auth.c —— FMDN 挑战-应答认证模块实现。
 * 详见 fmdn_auth.h 的接口说明。
 */

#include <rtthread.h>
#include <string.h>
#include <stdlib.h>

#include "mbedtls/md.h"

#include "fmdn_auth.h"
#include "fmdn_rng.h"   /* 硬件 TRNG(nonce 随机源) */

#define LOG_TAG "fmdn_auth"
#include "log.h"

/* AuthKey 消息最大长度:version(1) + nonce(8) + id(1) + len(1) + 附加数据
 * 附加数据最大为 SET_EIK 的 32B 加密 EIK(+8B 可选 hash),取 64 余量。 */
#define FMDN_AUTH_MSG_MAX   (1 + FMDN_NONCE_LEN + 1 + 1 + 64)

// ============================================================
// 子密钥派生:SHA256(EIK || suffix)[:8]
// ============================================================
int fmdn_auth_derive_subkey(const uint8_t eik[32], uint8_t suffix,
                            uint8_t out[FMDN_AUTH_TAG_LEN])
{
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    uint8_t buf[33];
    uint8_t hash[32];
    int ret;

    if (info == NULL)
    {
        LOG_E("SHA256 md_info not available");
        return -1;
    }

    memcpy(buf, eik, 32);
    buf[32] = suffix;                 /* EIK || suffix */

    ret = mbedtls_md(info, buf, sizeof(buf), hash);
    if (ret != 0)
    {
        LOG_E("SHA256 failed: %d", ret);
        return ret;
    }

    memcpy(out, hash, FMDN_AUTH_TAG_LEN);  /* 取前 8 字节 */
    return 0;
}

// ============================================================
// EIK hash:SHA256(EIK || nonce)[:8]
// ============================================================
// 用于 SET_EIK(换钥)/ CLEAR_EIK / 关闭 UT 时证明对方确实掌握
// 当前 EIK(规范 Table 2 / Clear EIK / Table 5 的附加数据)。
int fmdn_auth_eik_hash(const uint8_t eik[32],
                       const uint8_t nonce[FMDN_NONCE_LEN],
                       uint8_t out[FMDN_AUTH_TAG_LEN])
{
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    uint8_t buf[32 + FMDN_NONCE_LEN];
    uint8_t hash[32];
    int ret;

    if (info == NULL)
    {
        LOG_E("SHA256 md_info not available");
        return -1;
    }

    memcpy(buf, eik, 32);
    memcpy(buf + 32, nonce, FMDN_NONCE_LEN);   /* EIK || nonce */

    ret = mbedtls_md(info, buf, sizeof(buf), hash);
    if (ret != 0)
    {
        LOG_E("SHA256 failed: %d", ret);
        return ret;
    }

    memcpy(out, hash, FMDN_AUTH_TAG_LEN);       /* 取前 8 字节 */
    return 0;
}

// ============================================================
// HMAC-SHA256
// ============================================================
int fmdn_hmac_sha256(const uint8_t *key, uint32_t key_len,
                     const uint8_t *msg, uint32_t msg_len,
                     uint8_t out[32])
{
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (info == NULL)
    {
        LOG_E("SHA256 md_info not available");
        return -1;
    }
    return mbedtls_md_hmac(info, key, key_len, msg, msg_len, out);
}

// ============================================================
// AuthKey 计算 / 校验
// ============================================================

/* 按规范拼接认证消息:version || nonce || data_id || data_len || add_data */
static uint32_t fmdn_auth_build_msg(uint8_t protocol_version,
                                    const uint8_t nonce[FMDN_NONCE_LEN],
                                    uint8_t data_id, uint8_t data_len,
                                    const uint8_t *add_data, uint32_t add_data_len,
                                    uint8_t *msg_out)
{
    uint32_t off = 0;

    msg_out[off++] = protocol_version;
    memcpy(&msg_out[off], nonce, FMDN_NONCE_LEN);
    off += FMDN_NONCE_LEN;
    msg_out[off++] = data_id;
    msg_out[off++] = data_len;

    if (add_data != NULL && add_data_len > 0)
    {
        memcpy(&msg_out[off], add_data, add_data_len);
        off += add_data_len;
    }
    return off;
}

int fmdn_auth_compute_tag(const uint8_t *key, uint32_t key_len,
                          uint8_t protocol_version,
                          const uint8_t nonce[FMDN_NONCE_LEN],
                          uint8_t data_id, uint8_t data_len,
                          const uint8_t *add_data, uint32_t add_data_len,
                          uint8_t tag_out[FMDN_AUTH_TAG_LEN])
{
    uint8_t msg[FMDN_AUTH_MSG_MAX];
    uint8_t full[32];
    int ret;

    if (add_data_len > FMDN_AUTH_MSG_MAX - (1 + FMDN_NONCE_LEN + 2))
    {
        LOG_E("auth add_data too long: %u", add_data_len);
        return -1;
    }

    uint32_t msg_len = fmdn_auth_build_msg(protocol_version, nonce,
                                           data_id, data_len,
                                           add_data, add_data_len, msg);

    ret = fmdn_hmac_sha256(key, key_len, msg, msg_len, full);
    if (ret != 0)
    {
        LOG_E("HMAC failed: %d", ret);
        return ret;
    }

    memcpy(tag_out, full, FMDN_AUTH_TAG_LEN);  /* 取前 8 字节 */
    return 0;
}

/* 常量时间比较,避免按字节提前返回造成的时序侧信道 */
static bool fmdn_const_time_equal(const uint8_t *a, const uint8_t *b, uint32_t len)
{
    uint8_t diff = 0;
    for (uint32_t i = 0; i < len; i++)
        diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

bool fmdn_auth_verify(const uint8_t *key, uint32_t key_len,
                      uint8_t protocol_version,
                      const uint8_t nonce[FMDN_NONCE_LEN],
                      uint8_t data_id, uint8_t data_len,
                      const uint8_t *add_data, uint32_t add_data_len,
                      const uint8_t recv_tag[FMDN_AUTH_TAG_LEN])
{
    uint8_t expect[FMDN_AUTH_TAG_LEN];

    if (fmdn_auth_compute_tag(key, key_len, protocol_version, nonce,
                              data_id, data_len, add_data, add_data_len,
                              expect) != 0)
        return false;

    return fmdn_const_time_equal(expect, recv_tag, FMDN_AUTH_TAG_LEN);
}

bool fmdn_auth_verify_eik_hash(const uint8_t eik[32],
                               const uint8_t nonce[FMDN_NONCE_LEN],
                               const uint8_t recv_hash[FMDN_AUTH_TAG_LEN])
{
    uint8_t expect[FMDN_AUTH_TAG_LEN];

    if (fmdn_auth_eik_hash(eik, nonce, expect) != 0)
        return false;

    return fmdn_const_time_equal(expect, recv_hash, FMDN_AUTH_TAG_LEN);
}

int fmdn_auth_compute_resp_tag(const uint8_t *key, uint32_t key_len,
                               uint8_t protocol_version,
                               const uint8_t nonce[FMDN_NONCE_LEN],
                               uint8_t data_id, uint8_t data_len,
                               const uint8_t *add_data, uint32_t add_data_len,
                               uint8_t tag_out[FMDN_AUTH_TAG_LEN])
{
    uint8_t msg[FMDN_AUTH_MSG_MAX];
    uint8_t full[32];
    int ret;

    if (add_data_len > FMDN_AUTH_MSG_MAX - (1 + FMDN_NONCE_LEN + 2 + 1))
    {
        LOG_E("resp auth add_data too long: %u", add_data_len);
        return -1;
    }

    uint32_t msg_len = fmdn_auth_build_msg(protocol_version, nonce,
                                           data_id, data_len,
                                           add_data, add_data_len, msg);
    msg[msg_len++] = 0x01;   /* 响应认证段消息尾部追加 0x01 */

    ret = fmdn_hmac_sha256(key, key_len, msg, msg_len, full);
    if (ret != 0)
    {
        LOG_E("resp HMAC failed: %d", ret);
        return ret;
    }

    memcpy(tag_out, full, FMDN_AUTH_TAG_LEN);
    return 0;
}

// ============================================================
// 一次性 nonce 生命周期
// ============================================================

void fmdn_nonce_refresh(fmdn_nonce_t *n)
{
    /* 用硬件 TRNG 生成 nonce;若 TRNG 不可用,fmdn_rng_fill 内部回退到 rand() */
    fmdn_rng_fill(n->value, FMDN_NONCE_LEN);
    n->valid = true;
}

bool fmdn_nonce_consume(fmdn_nonce_t *n, uint8_t out[FMDN_NONCE_LEN])
{
    if (!n->valid)
        return false;

    if (out != NULL)
        memcpy(out, n->value, FMDN_NONCE_LEN);

    n->valid = false;   /* 用过即失效,无论后续操作成败 */
    return true;
}
