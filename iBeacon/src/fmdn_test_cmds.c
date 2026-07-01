/*
 * SPDX-FileCopyrightText: 2024-2024 SiFli Technologies(Nanjing) Co., Ltd
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * fmdn_test_cmds.c —— FMDN 标签的串口测试与调试命令。
 *
 * 这些命令仅用于开发/验证,不属于最终出厂的 FMDN 行为。它们通过
 * fmdn.h 调用 main.c 导出的核心函数(配网捷径、EID 自测、AES 自测、
 * 生成 GATT 写命令、广播启停)。
 *
 * 命令列表:
 *   cmd_diss          BLE 广播启动/停止控制
 *   cmd_fmdn_ak       设置 Account Key(16 字节 / 32 hex)
 *   cmd_fmdn_stat     查看设备状态(是否配置 AK / EIK)
 *   cmd_fmdn_time     设置 Unix 时间戳(用于 EID 轮换同步)
 *   cmd_fmdn_eik      直接设置 EIK(明文,绕过 GATT)
 *   cmd_fmdn_eid_test 计算并打印当前 EID
 *   cmd_fmdn_debug    逐步打印 EID 生成过程(与 Python 比对)
 *   cmd_fmdn_aes      AES-ECB-128 加解密往返自测
 *   cmd_fmdn_gen      生成可粘贴到 nRF Connect 的 SET_EIK 写命令
 */

#include <rtthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "mbedtls/aes.h"
#include "mbedtls/bignum.h"

#include "fmdn.h"
#include "fmdn_auth.h"
#include "fmdn_store.h"

#define LOG_TAG "fmdn_test"
#include "log.h"

// ------------------------------------------------------------
// BLE 广播启动/停止控制
//   用法:cmd_diss adv_start | cmd_diss adv_stop
// ------------------------------------------------------------
int cmd_diss(int argc, char *argv[])
{
    if (argc > 1)
    {
        if (strcmp(argv[1], "adv_start") == 0)
            ble_app_adv_start();
        else if (strcmp(argv[1], "adv_stop") == 0)
            ble_app_adv_stop();
    }
    return 0;
}

#ifdef RT_USING_FINSH
    MSH_CMD_EXPORT(cmd_diss, BLE advertising start/stop control);
#endif

// ------------------------------------------------------------
// 设置 Account Key(测试用)
//   用法:cmd_fmdn_ak <32 个 hex 字符>
//   示例:cmd_fmdn_ak 00112233445566778899AABBCCDDEEFF
// ------------------------------------------------------------
static int cmd_fmdn_ak(int argc, char *argv[])
{
    app_env_t *env = ble_app_get_env();

    if (argc < 2)
    {
        LOG_I("Usage: fmdn_ak <32-hex-chars-Account-Key>");
        LOG_I("Current Account Key:");
        LOG_HEX("AK", 16, env->account_key, 16);
        LOG_I("Provisioned: %s", env->is_provisioned ? "YES" : "NO");
        if (env->is_provisioned)
            LOG_HEX("EIK", 16, env->eik, 32);
        return 0;
    }

    const char *hex = argv[1];
    if (rt_strlen(hex) < 32)
    {
        LOG_E("Need 32 hex chars (16 bytes)");
        return -1;
    }

    // 把 hex 字符串解析为字节
    for (int i = 0; i < 16; i++)
    {
        char byte_str[3] = {hex[i * 2], hex[i * 2 + 1], '\0'};
        env->account_key[i] = (uint8_t)strtol(byte_str, NULL, 16);
    }

    LOG_HEX("Account Key set", 16, env->account_key, 16);
    fmdn_account_key_provisioned();   // 启动 5 分钟未配网保护(模拟"配对后"触发点)
    return 0;
}
MSH_CMD_EXPORT(cmd_fmdn_ak, Set FMDN Account Key (32 hex chars));

// ------------------------------------------------------------
// 查看 FMDN 设备状态
// ------------------------------------------------------------
static int cmd_fmdn_stat(int argc, char *argv[])
{
    app_env_t *env = ble_app_get_env();

    LOG_I("=== FMDN Device Status ===");
    LOG_I("Provisioned: %s", env->is_provisioned ? "YES" : "NO");
    LOG_I("Has account key: %s, Owner key locked: %s, UT: %s",
          env->has_account_key ? "YES" : "NO",
          env->has_owner_key ? "YES" : "NO",
          env->ut_mode ? "ON" : "OFF");
    LOG_HEX("Account Key", 16, env->account_key, 16);
    if (env->is_provisioned)
        LOG_HEX("EIK", 16, env->eik, 32);
    return 0;
}
MSH_CMD_EXPORT(cmd_fmdn_stat, Show FMDN device status);

// ------------------------------------------------------------
// 设置当前 Unix 时间戳(用于 EID 轮换同步)
//   用法:cmd_fmdn_time <unix 秒数>
//   获取当前 Unix 时间:https://www.unixtimestamp.com
// ------------------------------------------------------------
static int cmd_fmdn_time(int argc, char *argv[])
{
    app_env_t *env = ble_app_get_env();

    if (argc < 2)
    {
        uint32_t now = fmdn_get_timestamp();
        LOG_I("Current Unix time: %u", now);
        LOG_I("(masked: %u)", now & ~((1u << FMDN_EID_ROTATION_K) - 1));
        return 0;
    }

    uint32_t unix_now = (uint32_t)atol(argv[1]);
    uint32_t boot_sec = (uint32_t)(rt_tick_get() / RT_TICK_PER_SECOND);
    env->unix_time_offset = unix_now - boot_sec;
    fmdn_store_save_clock(unix_now);   // 持久化时钟(断电恢复)

    LOG_I("Unix time set: %u (offset=%u, boot=%u)", unix_now, env->unix_time_offset, boot_sec);

    // 用新时间重新生成 EID
    if (env->is_provisioned)
        fmdn_eid_update();

    return 0;
}
MSH_CMD_EXPORT(cmd_fmdn_time, Set Unix timestamp for EID sync);

// ------------------------------------------------------------
// 快速测试:直接设置 EIK(绕过 GATT + 加密)
//   用法:cmd_fmdn_eik <64 个 hex 字符>(32 字节明文 EIK)
// ------------------------------------------------------------
static int cmd_fmdn_eik(int argc, char *argv[])
{
    app_env_t *env = ble_app_get_env();

    if (argc < 2 || rt_strlen(argv[1]) < 64)
    {
        LOG_E("Usage: fmdn_set_eik <64-hex-chars>  (32 bytes plaintext EIK)");
        return -1;
    }

    const char *hex = argv[1];
    for (int i = 0; i < 32; i++)
    {
        char byte_str[3] = {hex[i * 2], hex[i * 2 + 1], '\0'};
        env->eik[i] = (uint8_t)strtol(byte_str, NULL, 16);
    }

    env->is_provisioned = 1;
    LOG_I("EIK set directly (bypassing GATT)");
    LOG_HEX("EIK", 16, env->eik, 32);
    LOG_I("Device is now PROVISIONED!");
    fmdn_store_save(env);      // 持久化:配网状态写入 flash
    fmdn_eid_update();         // 生成第一个 EID
    fmdn_eid_timer_start();    // 启动轮换定时器
    return 0;
}
MSH_CMD_EXPORT(cmd_fmdn_eik, Set EIK directly);

// ------------------------------------------------------------
// 用当前 EIK 测试 EID 生成
// ------------------------------------------------------------
static int cmd_fmdn_eid_test(int argc, char *argv[])
{
    app_env_t *env = ble_app_get_env();

    if (!env->is_provisioned)
    {
        LOG_E("Not provisioned! Run: cmd_fmdn_ak / cmd_fmdn_eik first");
        return -1;
    }

    uint32_t ts = fmdn_get_timestamp();
    LOG_I("Timestamp: %u seconds since boot", ts);
    LOG_I("Masked ts:  %u", ts & ~((1u << FMDN_EID_ROTATION_K) - 1));

    uint8_t eid[FMDN_EID_LEN];
    int ret = fmdn_eid_generate(env->eik, ts, eid, NULL);
    if (ret == 0)
    {
        LOG_HEX("Generated EID", 16, eid, FMDN_EID_LEN);
        LOG_I("EID generation: OK (20 bytes)");
    }
    else
    {
        LOG_E("EID generation failed: %d", ret);
    }
    return ret;
}
MSH_CMD_EXPORT(cmd_fmdn_eid_test, Test EID generation with current EIK);

// ------------------------------------------------------------
// 调试:逐步打印 EID 生成过程,用于与 Python 比对
// ------------------------------------------------------------
static int cmd_fmdn_debug(int argc, char *argv[])
{
    app_env_t *env = ble_app_get_env();
    if (!env->is_provisioned) { LOG_E("Not provisioned!"); return -1; }

    uint32_t ts = fmdn_get_timestamp();
    uint32_t masked = ts & ~((1u << FMDN_EID_ROTATION_K) - 1);

    uint8_t ts_block[32];
    memset(ts_block, 0xFF, 11);
    ts_block[11] = FMDN_EID_ROTATION_K;
    ts_block[12] = (uint8_t)(masked >> 24);
    ts_block[13] = (uint8_t)(masked >> 16);
    ts_block[14] = (uint8_t)(masked >> 8);
    ts_block[15] = (uint8_t)(masked & 0xFF);
    memset(&ts_block[16], 0, 11);
    ts_block[27] = FMDN_EID_ROTATION_K;
    ts_block[28] = (uint8_t)(masked >> 24);
    ts_block[29] = (uint8_t)(masked >> 16);
    ts_block[30] = (uint8_t)(masked >> 8);
    ts_block[31] = (uint8_t)(masked & 0xFF);

    LOG_HEX("DEBUG: ts_block[0-15]", 16, ts_block, 16);
    LOG_HEX("DEBUG: ts_block[16-31]", 16, &ts_block[16], 16);

    uint8_t r_bytes[32];
    aes_ecb_256_encrypt_block32(env->eik, ts_block, r_bytes);
    LOG_HEX("DEBUG: AES-ECB-256 output", 16, r_bytes, 32);

    mbedtls_mpi r_prime, n, r;
    mbedtls_mpi_init(&r_prime);
    mbedtls_mpi_init(&n);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_read_binary(&r_prime, r_bytes, 32);
    mbedtls_mpi_read_string(&n, 16, SECP160R1_N);
    mbedtls_mpi_mod_mpi(&r, &r_prime, &n);

    // 把 r(大端)打印出来与 Python 比对
    uint8_t r_buf[21] = {0}; // 161 位的 n 最多需要 21 字节
    mbedtls_mpi_write_binary(&r, r_buf, 21);
    LOG_HEX("DEBUG: r = r_prime mod n", 16, r_buf, 21);

    mbedtls_mpi_free(&r_prime);
    mbedtls_mpi_free(&n);
    mbedtls_mpi_free(&r);
    return 0;
}
MSH_CMD_EXPORT(cmd_fmdn_debug, Debug EID generation step-by-step);

// ------------------------------------------------------------
// 自测:AES-ECB-128 加解密往返(加密 -> 解密)
// ------------------------------------------------------------
static int cmd_fmdn_aes(int argc, char *argv[])
{
    app_env_t *env = ble_app_get_env();

    // 使用当前 account key,若未设置则用一个测试密钥
    uint8_t test_key[16];
    uint8_t test_plain[16] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77
    };

    // 若已设置 Account Key 则用它,否则用测试密钥
    int is_zero = 1;
    for (int i = 0; i < 16; i++)
        if (env->account_key[i] != 0) is_zero = 0;

    if (is_zero)
    {
        // 生成一个测试用 Account Key
        for (int i = 0; i < 16; i++)
            test_key[i] = (uint8_t)i;
        LOG_I("Using test Account Key: 00 01 02 ... 0F");
    }
    else
    {
        memcpy(test_key, env->account_key, 16);
        LOG_HEX("Using current Account Key", 16, test_key, 16);
    }

    uint8_t encrypted[16], decrypted[16];

    int ret = aes_ecb_128_crypt(test_key, test_plain, encrypted, MBEDTLS_AES_ENCRYPT);
    if (ret != 0)
    {
        LOG_E("Encrypt failed: %d", ret);
        return -1;
    }

    ret = aes_ecb_128_crypt(test_key, encrypted, decrypted, MBEDTLS_AES_DECRYPT);
    if (ret != 0)
    {
        LOG_E("Decrypt failed: %d", ret);
        return -1;
    }

    int match = (memcmp(test_plain, decrypted, 16) == 0);
    LOG_I("AES-ECB-128 round-trip test: %s", match ? "PASS" : "FAIL");
    LOG_HEX("Plaintext", 16, test_plain, 16);
    LOG_HEX("Encrypted", 16, encrypted, 16);
    LOG_HEX("Decrypted", 16, decrypted, 16);

    return match ? 0 : -1;
}
MSH_CMD_EXPORT(cmd_fmdn_aes, Self-test AES-ECB-128 round-trip);

// ------------------------------------------------------------
// 用 Account Key 加密 EIK,打印出可用于 GATT 写入的原始字节
//   用法:cmd_fmdn_gen(打印可粘贴到 nRF Connect Write 的 hex)
// ------------------------------------------------------------
static int cmd_fmdn_gen(int argc, char *argv[])
{
    app_env_t *env = ble_app_get_env();

    if (!env->is_provisioned)
    {
        LOG_E("Not provisioned! Set EIK first: cmd_fmdn_eik <64 hex>");
        return -1;
    }

    uint8_t encrypted[32];
    int ret;

    // 用 Account Key 分块加密 EIK
    ret = aes_ecb_128_crypt(env->account_key, &env->eik[0],
                             &encrypted[0], MBEDTLS_AES_ENCRYPT);
    if (ret) { LOG_E("Block 1 failed"); return -1; }
    ret = aes_ecb_128_crypt(env->account_key, &env->eik[16],
                             &encrypted[16], MBEDTLS_AES_ENCRYPT);
    if (ret) { LOG_E("Block 2 failed"); return -1; }

    // 构造 SET_EIK 写命令:[02][20][0000000000000000][加密的32B]
    uint8_t cmd[42];
    cmd[0] = 0x02;  // DataID = SET_EIK
    cmd[1] = 0x20;  // DataLen = 32
    memset(&cmd[2], 0, 8);  // AuthKey 占位
    memcpy(&cmd[10], encrypted, 32);

    LOG_I("=== SET_EIK GATT Write command (42 bytes) ===");
    LOG_HEX("CMD", 16, cmd, 42);
    LOG_I("=== Copy the 42 bytes above to nRF Connect ===");

    return 0;
}
MSH_CMD_EXPORT(cmd_fmdn_gen, Generate SET_EIK write data for nRF Connect);

// ------------------------------------------------------------
// 把一串 hex 文本解析为字节数组,返回解析出的字节数(失败返回 -1)
// ------------------------------------------------------------
static int fmdn_parse_hex(const char *hex, uint8_t *out, int max_len)
{
    int len = (int)rt_strlen(hex);
    if (len % 2 != 0) return -1;          // 必须偶数个 hex 字符
    int n = len / 2;
    if (n > max_len) return -1;
    for (int i = 0; i < n; i++)
    {
        char byte_str[3] = {hex[i * 2], hex[i * 2 + 1], '\0'};
        char *end = NULL;
        long v = strtol(byte_str, &end, 16);
        if (end != byte_str + 2) return -1; // 含非法 hex 字符
        out[i] = (uint8_t)v;
    }
    return n;
}

// ------------------------------------------------------------
// 生成带正确 AuthKey 的 Beacon Actions 写命令(用 Account Key 认证)
//   用法:cmd_fmdn_authcmd <DataID 2hex> <nonce 16hex> [附加数据 hex]
//   示例(0x00 读参数):cmd_fmdn_authcmd 00 1122334455667788
//   示例(0x01 读配网):cmd_fmdn_authcmd 01 <nonce16hex>
//   流程:先在 nRF Read 拿到 nonce(返回值第 2~9 字节),填到这里,
//        本命令算出 AuthKey 并打印完整写命令,粘贴回 nRF Write。
// ------------------------------------------------------------
static int cmd_fmdn_authcmd(int argc, char *argv[])
{
    app_env_t *env = ble_app_get_env();

    if (argc < 3)
    {
        LOG_I("Usage: cmd_fmdn_authcmd <DataID 2hex> <nonce 16hex> [addData hex]");
        LOG_I("  e.g. cmd_fmdn_authcmd 00 <16-hex-nonce>");
        return -1;
    }

    // 解析 DataID
    uint8_t data_id;
    if (fmdn_parse_hex(argv[1], &data_id, 1) != 1)
    {
        LOG_E("bad DataID (need 2 hex chars)");
        return -1;
    }

    // 解析 nonce(必须 8 字节 = 16 hex)
    uint8_t nonce[FMDN_NONCE_LEN];
    if (fmdn_parse_hex(argv[2], nonce, FMDN_NONCE_LEN) != FMDN_NONCE_LEN)
    {
        LOG_E("bad nonce (need 16 hex chars = 8 bytes)");
        return -1;
    }

    // 解析可选附加数据
    uint8_t add_data[64];
    int add_len = 0;
    if (argc >= 4)
    {
        add_len = fmdn_parse_hex(argv[3], add_data, sizeof(add_data));
        if (add_len < 0)
        {
            LOG_E("bad addData hex");
            return -1;
        }
    }

    uint8_t data_len = (uint8_t)add_len;

    // 按操作类型选择认证密钥(与设备端 fmdn_gatts_set_cbk 逻辑一致)
    const uint8_t *key;
    uint32_t key_len;
    uint8_t subkey[FMDN_AUTH_TAG_LEN];

    if (data_id <= FMDN_DATA_ID_CLEAR_EIK)        // 0x00-0x03 → Account Key
    {
        key = env->account_key;
        key_len = 16;
    }
    else                                          // 0x04-0x08 → EIK 派生子密钥
    {
        uint8_t suffix;
        if (data_id == FMDN_DATA_ID_READ_EIK)              suffix = FMDN_SUBKEY_RECOVERY;
        else if (data_id == FMDN_DATA_ID_RING ||
                 data_id == FMDN_DATA_ID_READ_RING_STATE)  suffix = FMDN_SUBKEY_RING;
        else if (data_id == FMDN_DATA_ID_ENABLE_UT ||
                 data_id == FMDN_DATA_ID_DISABLE_UT)       suffix = FMDN_SUBKEY_UT;
        else { LOG_E("unsupported DataID 0x%02X", data_id); return -1; }

        if (!env->is_provisioned)
        {
            LOG_E("not provisioned: need EIK to derive subkey");
            return -1;
        }
        if (fmdn_auth_derive_subkey(env->eik, suffix, subkey) != 0)
        {
            LOG_E("derive subkey failed");
            return -1;
        }
        key = subkey;
        key_len = FMDN_AUTH_TAG_LEN;
    }

    // 计算 AuthKey = HMAC-SHA256(key, ver||nonce||id||len||addData)[:8]
    uint8_t tag[FMDN_AUTH_TAG_LEN];
    int ret = fmdn_auth_compute_tag(key, key_len, FMDN_PROTOCOL_VERSION,
                                    nonce, data_id, data_len,
                                    add_len ? add_data : NULL, (uint32_t)add_len,
                                    tag);
    if (ret != 0)
    {
        LOG_E("compute tag failed: %d", ret);
        return -1;
    }

    // 拼出完整写命令:[DataID][DataLen][AuthKey(8B)][附加数据]
    uint8_t cmd[2 + FMDN_AUTH_TAG_LEN + 64];
    int off = 0;
    cmd[off++] = data_id;
    cmd[off++] = data_len;
    rt_memcpy(&cmd[off], tag, FMDN_AUTH_TAG_LEN);
    off += FMDN_AUTH_TAG_LEN;
    if (add_len > 0)
    {
        rt_memcpy(&cmd[off], add_data, add_len);
        off += add_len;
    }

    LOG_I("=== Authenticated Write command (%d bytes) ===", off);
    LOG_HEX("CMD", 16, cmd, off);
    LOG_I("=== Copy to nRF Connect Write (BYTE ARRAY) ===");
    return 0;
}
MSH_CMD_EXPORT(cmd_fmdn_authcmd, Generate authenticated Beacon Actions write command);

// ------------------------------------------------------------
// 打印从当前 EIK 派生的三个子密钥(用于与 Python 比对)
//   Recovery = SHA256(EIK||0x01)[:8]
//   Ring     = SHA256(EIK||0x02)[:8]
//   UT       = SHA256(EIK||0x03)[:8]
// ------------------------------------------------------------
static int cmd_fmdn_subkeys(int argc, char *argv[])
{
    app_env_t *env = ble_app_get_env();
    uint8_t k[FMDN_AUTH_TAG_LEN];

    if (!env->is_provisioned)
    {
        LOG_E("Not provisioned! Set EIK first");
        return -1;
    }

    if (fmdn_auth_derive_subkey(env->eik, FMDN_SUBKEY_RECOVERY, k) == 0)
        LOG_HEX("Recovery Key", 16, k, FMDN_AUTH_TAG_LEN);
    if (fmdn_auth_derive_subkey(env->eik, FMDN_SUBKEY_RING, k) == 0)
        LOG_HEX("Ring Key", 16, k, FMDN_AUTH_TAG_LEN);
    if (fmdn_auth_derive_subkey(env->eik, FMDN_SUBKEY_UT, k) == 0)
        LOG_HEX("UT Key", 16, k, FMDN_AUTH_TAG_LEN);

    return 0;
}
MSH_CMD_EXPORT(cmd_fmdn_subkeys, Print Recovery/Ring/UT subkeys derived from EIK);

// ------------------------------------------------------------
// 计算当前 EIK hash = SHA256(EIK || nonce)[:8]
//   用于 0x02 换钥 / 0x03 CLEAR_EIK / 0x08 关闭 UT 的附加数据。
//   用法:cmd_fmdn_eikhash <nonce 16hex>
//   流程:nRF Read 拿到 nonce → 本命令算出 8 字节 hash →
//        作为 authcmd 的附加数据(0x02 则拼在 32B 加密EIK 之后)。
// ------------------------------------------------------------
static int cmd_fmdn_eikhash(int argc, char *argv[])
{
    app_env_t *env = ble_app_get_env();
    uint8_t nonce[FMDN_NONCE_LEN];
    uint8_t hash[FMDN_AUTH_TAG_LEN];

    if (!env->is_provisioned)
    {
        LOG_E("Not provisioned! Set EIK first");
        return -1;
    }
    if (argc < 2 || fmdn_parse_hex(argv[1], nonce, FMDN_NONCE_LEN) != FMDN_NONCE_LEN)
    {
        LOG_I("Usage: cmd_fmdn_eikhash <nonce 16hex>");
        return -1;
    }
    if (fmdn_auth_eik_hash(env->eik, nonce, hash) != 0)
    {
        LOG_E("eik hash compute failed");
        return -1;
    }
    LOG_HEX("EIK hash (append as addData)", 16, hash, FMDN_AUTH_TAG_LEN);
    return 0;
}
MSH_CMD_EXPORT(cmd_fmdn_eikhash, Compute SHA256(EIK||nonce)[:8] for clear/disable-UT/re-key);

// ------------------------------------------------------------
// 生成 0x02 换钥(re-key)的完整写命令
//   用法:cmd_fmdn_rekeycmd <新EIK 64hex> <nonce 16hex>
//   附加数据 = 32B(account key 加密的新 EIK) || 8B(旧 EIK hash)
//   旧 EIK hash = SHA256(当前EIK || nonce)[:8],证明掌握当前 EIK。
//   前提:设备已配网(否则无当前 EIK 可证明)。
//   流程:nRF Read 拿 nonce → 本命令生成写命令 → 粘贴回 nRF Write。
// ------------------------------------------------------------
static int cmd_fmdn_rekeycmd(int argc, char *argv[])
{
    app_env_t *env = ble_app_get_env();
    uint8_t new_eik[32];
    uint8_t nonce[FMDN_NONCE_LEN];
    const char *nonce_arg;

    // 内置默认的"待换新 EIK"(倒序值,便于和旧 000102..1F 区分),
    // 这样常用形式只需传 nonce,避免命令行过长被 msh 截断。
    static const uint8_t default_new_eik[32] = {
        0x1F, 0x1E, 0x1D, 0x1C, 0x1B, 0x1A, 0x19, 0x18,
        0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10,
        0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08,
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
    };

    if (!env->is_provisioned)
    {
        LOG_E("Not provisioned! re-key needs a current EIK");
        return -1;
    }

    // 两种正常用法 + 一个边界测试用法:
    //   cmd_fmdn_rekeycmd <nonce16hex>                 换钥:内置默认新 EIK(带 hash)
    //   cmd_fmdn_rekeycmd <newEIK64hex> <nonce16hex>   换钥:自定义新 EIK(带 hash)
    //   cmd_fmdn_rekeycmd nohash <nonce16hex>          测"已配网必须带 hash":生成不带 hash 的 0x02
    bool with_hash = true;
    if (argc >= 3 && strcmp(argv[1], "nohash") == 0)
    {
        memcpy(new_eik, default_new_eik, 32);  // 内容无所谓,反正应被 0x80 拒
        nonce_arg = argv[2];
        with_hash = false;
    }
    else if (argc == 2)
    {
        memcpy(new_eik, default_new_eik, 32);
        nonce_arg = argv[1];
    }
    else if (argc >= 3)
    {
        if (fmdn_parse_hex(argv[1], new_eik, 32) != 32)
        {
            LOG_E("bad newEIK (need 64 hex chars)");
            return -1;
        }
        nonce_arg = argv[2];
    }
    else
    {
        LOG_I("Usage: cmd_fmdn_rekeycmd <nonce16hex>            (use built-in new EIK)");
        LOG_I("       cmd_fmdn_rekeycmd <newEIK64hex> <nonce16hex>");
        LOG_I("       cmd_fmdn_rekeycmd nohash <nonce16hex>      (expect 0x80)");
        return -1;
    }

    if (fmdn_parse_hex(nonce_arg, nonce, FMDN_NONCE_LEN) != FMDN_NONCE_LEN)
    {
        LOG_E("bad nonce (need 16 hex chars = 8 bytes)");
        return -1;
    }

    // 附加数据:32B 加密新 EIK(2 个 AES-ECB-128 块) [+ 8B 旧 EIK hash]
    uint8_t add_data[40];
    if (aes_ecb_128_crypt(env->account_key, &new_eik[0],  &add_data[0],  MBEDTLS_AES_ENCRYPT) != 0 ||
        aes_ecb_128_crypt(env->account_key, &new_eik[16], &add_data[16], MBEDTLS_AES_ENCRYPT) != 0)
    {
        LOG_E("encrypt new EIK failed");
        return -1;
    }
    uint32_t add_len = 32;
    if (with_hash)
    {
        if (fmdn_auth_eik_hash(env->eik, nonce, &add_data[32]) != 0)
        {
            LOG_E("old EIK hash failed");
            return -1;
        }
        add_len = 40;
    }

    // AuthKey = HMAC(account key, ver||nonce||0x02||len||addData)[:8]
    uint8_t data_len = (uint8_t)add_len;   // 带 hash=0x28(40),不带=0x20(32)
    uint8_t tag[FMDN_AUTH_TAG_LEN];
    if (fmdn_auth_compute_tag(env->account_key, 16, FMDN_PROTOCOL_VERSION,
                              nonce, FMDN_DATA_ID_SET_EIK, data_len,
                              add_data, add_len, tag) != 0)
    {
        LOG_E("compute tag failed");
        return -1;
    }

    // 完整命令:[0x02][len][AuthKey 8B][addData]
    uint8_t cmd[2 + FMDN_AUTH_TAG_LEN + 40];
    int off = 0;
    cmd[off++] = FMDN_DATA_ID_SET_EIK;
    cmd[off++] = data_len;
    rt_memcpy(&cmd[off], tag, FMDN_AUTH_TAG_LEN);
    off += FMDN_AUTH_TAG_LEN;
    rt_memcpy(&cmd[off], add_data, add_len);
    off += add_len;

    LOG_I("=== %s Write command (%d bytes) ===", with_hash ? "Re-key" : "Re-key(no-hash)", off);
    LOG_HEX("REKEY CMD", 16, cmd, off);
    LOG_I("=== Copy to nRF Connect Write (BYTE ARRAY) ===");
    return 0;
}
MSH_CMD_EXPORT(cmd_fmdn_rekeycmd, Generate 0x02 re-key write command: [newEIK64hex] <nonce16hex>);

// ------------------------------------------------------------
// 出厂复位:清除 flash 中持久化的配网状态(用于测试持久化)
//   清完复位设备应回到未配网状态
// ------------------------------------------------------------
static int cmd_fmdn_factory(int argc, char *argv[])
{
    fmdn_factory_reset_now();   // 立即清 account key + EIK + 持久化,广播切占位
    LOG_I("Factory reset done");
    return 0;
}
MSH_CMD_EXPORT(cmd_fmdn_factory, Factory reset: clear account key + EIK + persisted state);

// ------------------------------------------------------------
// 切换配对模式(0x04 READ_EIK 需要在配对模式下才允许)
//   用法:cmd_fmdn_pairing on | off
// ------------------------------------------------------------
static int cmd_fmdn_pairing(int argc, char *argv[])
{
    app_env_t *env = ble_app_get_env();
    if (argc >= 2)
        env->pairing_mode = (strcmp(argv[1], "on") == 0) ? 1 : 0;
    LOG_I("Pairing mode: %s", env->pairing_mode ? "ON" : "OFF");
    return 0;
}
MSH_CMD_EXPORT(cmd_fmdn_pairing, Toggle pairing mode for READ_EIK: cmd_fmdn_pairing on|off);
