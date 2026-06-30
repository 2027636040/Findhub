/*
 * SPDX-FileCopyrightText: 2024-2024 SiFli Technologies(Nanjing) Co., Ltd
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * fmdn_store.c —— FMDN 配网状态持久化(FlashDB KVDB / FAL 分区模式实现)。
 * 详见 fmdn_store.h。
 *
 * 本板为 NOR + 无文件系统,故采用 FlashDB 的 FAL 分区模式,直接读写
 * flash 分区(不依赖文件系统)。
 *
 * 依赖:
 *   - FAL 分区 "fmdn"(见 customer/boards/.../hcpu/custom_mem_map.h 的
 *     FAL_PART_TABLE,以及 ptab.json 的 KVDB_FMDN_REGION)
 *   - proj.conf 开启 CONFIG_PKG_FDB_USING_FAL_MODE=y
 *
 * 存储以独立 KV 键的形式保存:prov(1B) / ak(16B) / eik(32B)。
 */

#include <rtthread.h>
#include <string.h>

#include <flashdb.h>

#include "fmdn_store.h"

#define LOG_TAG "fmdn_store"
#include "log.h"

#define FMDN_KVDB_NAME   "fmdn_kv"   /* KVDB 实例名      */
#define FMDN_KVDB_PART   "fmdn"      /* FAL 分区名        */

#define FMDN_KEY_PROV    "prov"      /* 配网标志(1B)    */
#define FMDN_KEY_AK      "ak"        /* Account Key(16B)*/
#define FMDN_KEY_EIK     "eik"       /* EIK(32B)         */
#define FMDN_KEY_CLOCK   "clk"       /* 时钟 Unix 秒(4B)*/

static struct fdb_kvdb  s_kvdb;
static struct rt_mutex  s_kvdb_mutex;
static bool             s_inited = false;

/* FlashDB 上锁/解锁回调 */
static void fmdn_kv_lock(fdb_db_t db)
{
    (void)db;
    rt_mutex_take(&s_kvdb_mutex, RT_WAITING_FOREVER);
}
static void fmdn_kv_unlock(fdb_db_t db)
{
    (void)db;
    rt_mutex_release(&s_kvdb_mutex);
}

/* 惰性初始化:首次调用时初始化 KVDB(FAL 模式) */
static int fmdn_store_ensure_init(void)
{
    fdb_err_t err;

    if (s_inited)
        return 0;

    rt_mutex_init(&s_kvdb_mutex, "fmdn_kv", RT_IPC_FLAG_FIFO);
    memset(&s_kvdb, 0, sizeof(s_kvdb));

    fdb_kvdb_control(&s_kvdb, FDB_KVDB_CTRL_SET_LOCK,   (void *)fmdn_kv_lock);
    fdb_kvdb_control(&s_kvdb, FDB_KVDB_CTRL_SET_UNLOCK, (void *)fmdn_kv_unlock);

    /* FAL 模式下第 3 个参数为 FAL 分区名 */
    err = fdb_kvdb_init(&s_kvdb, FMDN_KVDB_NAME, FMDN_KVDB_PART, NULL, NULL);
    if (err != FDB_NO_ERR)
    {
        LOG_E("kvdb init failed on partition '%s': %d", FMDN_KVDB_PART, err);
        return -1;
    }

    s_inited = true;
    LOG_I("kvdb '%s' ready on partition '%s'", FMDN_KVDB_NAME, FMDN_KVDB_PART);
    return 0;
}

int fmdn_store_save(const app_env_t *env)
{
    struct fdb_blob blob;
    uint8_t prov;

    if (fmdn_store_ensure_init() != 0)
        return -1;

    prov = env->is_provisioned;
    fdb_kv_set_blob(&s_kvdb, FMDN_KEY_AK,   fdb_blob_make(&blob, env->account_key, 16));
    fdb_kv_set_blob(&s_kvdb, FMDN_KEY_EIK,  fdb_blob_make(&blob, env->eik, 32));
    fdb_kv_set_blob(&s_kvdb, FMDN_KEY_PROV, fdb_blob_make(&blob, &prov, 1));

    LOG_I("FMDN state saved to flash (provisioned=%d)", prov);
    return 0;
}

int fmdn_store_load(app_env_t *env)
{
    struct fdb_blob blob;
    uint8_t prov = 0;

    if (fmdn_store_ensure_init() != 0)
        return -1;

    /* 先读配网标志;若不存在说明从未保存过 */
    fdb_kv_get_blob(&s_kvdb, FMDN_KEY_PROV, fdb_blob_make(&blob, &prov, 1));
    if (blob.saved.len == 0)
    {
        LOG_I("load: no saved state");
        return -1;
    }

    fdb_kv_get_blob(&s_kvdb, FMDN_KEY_AK,  fdb_blob_make(&blob, env->account_key, 16));
    fdb_kv_get_blob(&s_kvdb, FMDN_KEY_EIK, fdb_blob_make(&blob, env->eik, 32));
    env->is_provisioned = prov;

    LOG_I("FMDN state loaded from flash (provisioned=%d)", prov);
    return 0;
}

int fmdn_store_clear(void)
{
    if (fmdn_store_ensure_init() != 0)
        return -1;

    fdb_kv_del(&s_kvdb, FMDN_KEY_AK);
    fdb_kv_del(&s_kvdb, FMDN_KEY_EIK);
    fdb_kv_del(&s_kvdb, FMDN_KEY_PROV);

    LOG_I("FMDN state cleared from flash");
    return 0;
}

int fmdn_store_save_clock(uint32_t unix_time)
{
    struct fdb_blob blob;

    if (fmdn_store_ensure_init() != 0)
        return -1;

    fdb_kv_set_blob(&s_kvdb, FMDN_KEY_CLOCK,
                    fdb_blob_make(&blob, &unix_time, sizeof(unix_time)));
    return 0;
}

int fmdn_store_load_clock(uint32_t *unix_time)
{
    struct fdb_blob blob;

    if (fmdn_store_ensure_init() != 0)
        return -1;

    fdb_kv_get_blob(&s_kvdb, FMDN_KEY_CLOCK,
                    fdb_blob_make(&blob, unix_time, sizeof(*unix_time)));
    if (blob.saved.len == 0)
        return -1;   /* 无记录 */

    LOG_I("clock loaded from flash: %u", *unix_time);
    return 0;
}
