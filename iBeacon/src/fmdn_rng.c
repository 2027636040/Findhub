/*
 * SPDX-FileCopyrightText: 2024-2024 SiFli Technologies(Nanjing) Co., Ltd
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * fmdn_rng.c —— FMDN 硬件随机数(TRNG)封装实现。
 * 详见 fmdn_rng.h 的接口说明。
 */

#include <rtthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "bf0_hal.h"

#include "fmdn_rng.h"

#define LOG_TAG "fmdn_rng"
#include "log.h"

#ifdef HAL_RNG_MODULE_ENABLED
static RNG_HandleTypeDef s_rng;
static bool s_rng_ready = false;
#endif

int fmdn_rng_init(void)
{
#ifdef HAL_RNG_MODULE_ENABLED
    uint32_t seed = 0;

    memset(&s_rng, 0, sizeof(s_rng));
    s_rng.Instance = hwp_trng;

    if (HAL_RNG_Init(&s_rng) != HAL_OK)
    {
        LOG_E("TRNG init failed, fallback to rand()");
        s_rng_ready = false;
        return -1;
    }

    /* 先生成一次种子(硬件推荐流程),再用于后续随机数生成 */
    if (HAL_RNG_Generate(&s_rng, &seed, 1) != HAL_OK)
        LOG_W("TRNG seed generation failed");

    s_rng_ready = true;
    LOG_I("TRNG ready");
    return 0;
#else
    LOG_W("HAL_RNG not enabled, nonce will use rand()");
    return -1;
#endif
}

int fmdn_rng_fill(uint8_t *buf, size_t len)
{
    size_t i;

    if (buf == NULL || len == 0)
        return -1;

#ifdef HAL_RNG_MODULE_ENABLED
    if (s_rng_ready)
    {
        size_t off = 0;
        bool ok = true;

        while (off < len)
        {
            uint32_t v = 0;
            if (HAL_RNG_Generate(&s_rng, &v, 0) != HAL_OK)
            {
                LOG_W("TRNG generate failed, fallback to rand()");
                ok = false;
                break;
            }
            size_t n = (len - off > sizeof(v)) ? sizeof(v) : (len - off);
            memcpy(buf + off, &v, n);
            off += n;
        }
        if (ok)
            return 0;
    }
#endif

    /* 兜底:伪随机(量产不应命中,仅在 TRNG 不可用时保证功能) */
    for (i = 0; i < len; i++)
        buf[i] = (uint8_t)(rand() & 0xFF);
    return -1;
}
