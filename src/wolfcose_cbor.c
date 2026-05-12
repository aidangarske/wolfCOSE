/* wolfcose_cbor.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfCOSE.
 *
 * wolfCOSE is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfCOSE is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

/**
 * CBOR encoder/decoder per RFC 8949. Pure C99, no wolfCrypt dependency.
 * Zero-copy decode: bstr/tstr data pointers reference the input buffer.
 * Single-pass: decoder advances ctx->idx monotonically through the buffer.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include "wolfcose_internal.h"
#include <string.h>  /* memcpy */

/* -----
 * Internal: CBOR head encoder
 *
 * RFC 8949 Section 3.1: initial byte encoding
 *   initial_byte = (majorType << 5) | additional_info
 *   val <= 23:         1 byte  (val in low 5 bits)
 *   val <= 0xFF:       2 bytes (AI=24, then uint8)
 *   val <= 0xFFFF:     3 bytes (AI=25, then BE16)
 *   val <= 0xFFFFFFFF: 5 bytes (AI=26, then BE32)
 *   else:              9 bytes (AI=27, then BE64)
 * ----- */
int wolfCose_CBOR_EncodeHead(WOLFCOSE_CBOR_CTX* ctx, uint8_t majorType,
                              uint64_t val)
{
    int ret;

    if ((ctx == NULL) || (ctx->buf == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        uint8_t mt = (uint8_t)(majorType << 5);
        size_t need;

        if (val <= 23u) {
            need = 1;
            if ((ctx->idx + need) > ctx->bufSz) {
                ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
            }
            else {
                ctx->buf[ctx->idx] = (uint8_t)(mt | (uint8_t)val);
                ctx->idx += need;
                ret = WOLFCOSE_SUCCESS;
            }
        }
        else if (val <= 0xFFu) {
            need = 2;
            if ((ctx->idx + need) > ctx->bufSz) {
                ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
            }
            else {
                ctx->buf[ctx->idx]     = (uint8_t)(mt | WOLFCOSE_CBOR_AI_1BYTE);
                ctx->buf[ctx->idx + 1u] = (uint8_t)val;
                ctx->idx += need;
                ret = WOLFCOSE_SUCCESS;
            }
        }
        else if (val <= 0xFFFFu) {
            need = 3;
            if ((ctx->idx + need) > ctx->bufSz) {
                ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
            }
            else {
                ctx->buf[ctx->idx] = (uint8_t)(mt | WOLFCOSE_CBOR_AI_2BYTE);
                WOLFCOSE_STORE_BE16(&ctx->buf[ctx->idx + 1u], val);
                ctx->idx += need;
                ret = WOLFCOSE_SUCCESS;
            }
        }
        else if (val <= 0xFFFFFFFFu) {
            need = 5;
            if ((ctx->idx + need) > ctx->bufSz) {
                ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
            }
            else {
                ctx->buf[ctx->idx] = (uint8_t)(mt | WOLFCOSE_CBOR_AI_4BYTE);
                WOLFCOSE_STORE_BE32(&ctx->buf[ctx->idx + 1u], val);
                ctx->idx += need;
                ret = WOLFCOSE_SUCCESS;
            }
        }
        else {
            need = 9;
            if ((ctx->idx + need) > ctx->bufSz) {
                ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
            }
            else {
                ctx->buf[ctx->idx] = (uint8_t)(mt | WOLFCOSE_CBOR_AI_8BYTE);
                WOLFCOSE_STORE_BE64(&ctx->buf[ctx->idx + 1u], val);
                ctx->idx += need;
                ret = WOLFCOSE_SUCCESS;
            }
        }
    }
    return ret;
}

/* -----
 * Internal: CBOR head decoder
 *
 * Read initial byte, extract major type (bits 7-5) and AI (bits 4-0).
 * Based on AI: read 0/1/2/4/8 argument bytes.
 * AI 28-30 reserved = WOLFCOSE_E_CBOR_MALFORMED
 * AI 31 = WOLFCOSE_E_UNSUPPORTED (indefinite length -- COSE never uses it)
 *
 * For bstr/tstr: advances past the data and sets item->data/dataLen.
 * ----- */
int wolfCose_CBOR_DecodeHead(WOLFCOSE_CBOR_CTX* ctx, WOLFCOSE_CBOR_ITEM* item)
{
    int ret;
    uint8_t ib;
    uint8_t ai;

    if ((ctx == NULL) || (ctx->cbuf == NULL) || (item == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if (ctx->idx >= ctx->bufSz) {
        ret = WOLFCOSE_E_CBOR_MALFORMED;
    }
    else {
        ib = ctx->cbuf[ctx->idx];
        ctx->idx++;

        item->majorType = (uint8_t)(ib >> 5);
        ai = (uint8_t)(ib & 0x1Fu);
        item->data = NULL;
        item->dataLen = 0;

        if (ai <= 23u) {
            item->val = (uint64_t)ai;
            ret = WOLFCOSE_SUCCESS;
        }
        else if (ai == WOLFCOSE_CBOR_AI_1BYTE) {
            if ((ctx->idx + 1u) > ctx->bufSz) {
                ret = WOLFCOSE_E_CBOR_MALFORMED;
            }
            else {
                item->val = (uint64_t)ctx->cbuf[ctx->idx];
                ctx->idx += 1u;
                ret = WOLFCOSE_SUCCESS;
            }
        }
        else if (ai == WOLFCOSE_CBOR_AI_2BYTE) {
            if ((ctx->idx + 2u) > ctx->bufSz) {
                ret = WOLFCOSE_E_CBOR_MALFORMED;
            }
            else {
                item->val = (uint64_t)WOLFCOSE_LOAD_BE16(&ctx->cbuf[ctx->idx]);
                ctx->idx += 2u;
                ret = WOLFCOSE_SUCCESS;
            }
        }
        else if (ai == WOLFCOSE_CBOR_AI_4BYTE) {
            if ((ctx->idx + 4u) > ctx->bufSz) {
                ret = WOLFCOSE_E_CBOR_MALFORMED;
            }
            else {
                item->val = (uint64_t)WOLFCOSE_LOAD_BE32(&ctx->cbuf[ctx->idx]);
                ctx->idx += 4u;
                ret = WOLFCOSE_SUCCESS;
            }
        }
        else if (ai == WOLFCOSE_CBOR_AI_8BYTE) {
            if ((ctx->idx + 8u) > ctx->bufSz) {
                ret = WOLFCOSE_E_CBOR_MALFORMED;
            }
            else {
                item->val = WOLFCOSE_LOAD_BE64(&ctx->cbuf[ctx->idx]);
                ctx->idx += 8u;
                ret = WOLFCOSE_SUCCESS;
            }
        }
        else if (ai == WOLFCOSE_CBOR_AI_INDEF) {
            /* Indefinite length -- COSE never uses it */
            ret = WOLFCOSE_E_UNSUPPORTED;
        }
        else {
            /* AI 28-30 are reserved */
            ret = WOLFCOSE_E_CBOR_MALFORMED;
        }

        /* RFC 8949 Section 3.3: two-byte simple values (mt=7, AI=1B) with
         * arg < 32 are not well-formed and a decoder MUST reject them. */
        if ((ret == WOLFCOSE_SUCCESS) &&
            (item->majorType == WOLFCOSE_CBOR_SIMPLE) &&
            (ai == WOLFCOSE_CBOR_AI_1BYTE) &&
            (item->val < 32u)) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
        }

        /* For bstr/tstr, advance past the data bytes (zero-copy). The
         * bounds check is overflow-safe: we never add item->val to
         * ctx->idx in case the sum wraps; instead compare against the
         * remaining space. */
        if (ret == WOLFCOSE_SUCCESS) {
            if ((item->majorType == WOLFCOSE_CBOR_BSTR) ||
                (item->majorType == WOLFCOSE_CBOR_TSTR)) {
                if (item->val > (uint64_t)SIZE_MAX) {
                    ret = WOLFCOSE_E_CBOR_OVERFLOW;
                }
                else if ((size_t)item->val > (ctx->bufSz - ctx->idx)) {
                    ret = WOLFCOSE_E_CBOR_MALFORMED;
                }
                else {
                    item->data = &ctx->cbuf[ctx->idx];
                    item->dataLen = (size_t)item->val;
                    ctx->idx += (size_t)item->val;
                }
            }
        }
    }
    return ret;
}

/* -----
 * Public Encode API
 *
 * Guarded by WOLFCOSE_CBOR_ENCODE — can be excluded for decode-only builds.
 * ----- */

#if defined(WOLFCOSE_CBOR_ENCODE)

int wc_CBOR_EncodeUint(WOLFCOSE_CBOR_CTX* ctx, uint64_t val)
{
    return wolfCose_CBOR_EncodeHead(ctx, WOLFCOSE_CBOR_UINT, val);
}

int wc_CBOR_EncodeInt(WOLFCOSE_CBOR_CTX* ctx, int64_t val)
{
    int ret;

    if (ctx == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        if (val >= 0) {
            ret = wolfCose_CBOR_EncodeHead(ctx, WOLFCOSE_CBOR_UINT,
                                            (uint64_t)val);
        }
        else {
            /* RFC 8949: negative integer n is encoded as -(n+1) */
            ret = wolfCose_CBOR_EncodeHead(ctx, WOLFCOSE_CBOR_NEGINT,
                                            (uint64_t)(-(val + 1)));
        }
    }
    return ret;
}

/* Shared encode for bstr (major type 2) and tstr (major type 3) */
static int wolfCose_CBOR_EncodeBytes(WOLFCOSE_CBOR_CTX* ctx,
                                       uint8_t majorType,
                                       const uint8_t* data, size_t len)
{
    int ret;

    /* Reject NULL data paired with a non-zero length so the function
     * cannot leak uninitialised buffer contents. */
    if ((data == NULL) && (len > 0u)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        ret = wolfCose_CBOR_EncodeHead(ctx, majorType, (uint64_t)len);
        if (ret == WOLFCOSE_SUCCESS) {
            /* Overflow-safe: never compute idx + len when len could be
             * near SIZE_MAX. */
            if (len > (ctx->bufSz - ctx->idx)) {
                ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
            }
            else {
                if (len > 0u) {
                    (void)XMEMMOVE(&ctx->buf[ctx->idx], data, len);
                }
                ctx->idx += len;
            }
        }
    }
    return ret;
}

int wc_CBOR_EncodeBstr(WOLFCOSE_CBOR_CTX* ctx, const uint8_t* data,
                        size_t len)
{
    return wolfCose_CBOR_EncodeBytes(ctx, WOLFCOSE_CBOR_BSTR, data, len);
}

int wc_CBOR_EncodeTstr(WOLFCOSE_CBOR_CTX* ctx, const uint8_t* str,
                        size_t len)
{
    return wolfCose_CBOR_EncodeBytes(ctx, WOLFCOSE_CBOR_TSTR, str, len);
}

int wc_CBOR_EncodeArrayStart(WOLFCOSE_CBOR_CTX* ctx, size_t count)
{
    return wolfCose_CBOR_EncodeHead(ctx, WOLFCOSE_CBOR_ARRAY,
                                     (uint64_t)count);
}

int wc_CBOR_EncodeMapStart(WOLFCOSE_CBOR_CTX* ctx, size_t count)
{
    return wolfCose_CBOR_EncodeHead(ctx, WOLFCOSE_CBOR_MAP,
                                     (uint64_t)count);
}

int wc_CBOR_EncodeTag(WOLFCOSE_CBOR_CTX* ctx, uint64_t tag)
{
    return wolfCose_CBOR_EncodeHead(ctx, WOLFCOSE_CBOR_TAG, tag);
}

/* Shared single-byte simple value encoder (true, false, null) */
static int wolfCose_CBOR_EncodeSimpleVal(WOLFCOSE_CBOR_CTX* ctx, uint8_t val)
{
    int ret;

    if ((ctx == NULL) || (ctx->buf == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if ((ctx->idx + 1u) > ctx->bufSz) {
        ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
    }
    else {
        ctx->buf[ctx->idx] = val;
        ctx->idx++;
        ret = WOLFCOSE_SUCCESS;
    }
    return ret;
}

int wc_CBOR_EncodeTrue(WOLFCOSE_CBOR_CTX* ctx)
{
    return wolfCose_CBOR_EncodeSimpleVal(ctx, (uint8_t)WOLFCOSE_CBOR_TRUE);
}

int wc_CBOR_EncodeFalse(WOLFCOSE_CBOR_CTX* ctx)
{
    return wolfCose_CBOR_EncodeSimpleVal(ctx, (uint8_t)WOLFCOSE_CBOR_FALSE);
}

int wc_CBOR_EncodeNull(WOLFCOSE_CBOR_CTX* ctx)
{
    return wolfCose_CBOR_EncodeSimpleVal(ctx, (uint8_t)WOLFCOSE_CBOR_NULL);
}

#ifdef WOLFCOSE_FLOAT
int wc_CBOR_EncodeFloat(WOLFCOSE_CBOR_CTX* ctx, float val)
{
    int ret;
    uint32_t bits;

    if ((ctx == NULL) || (ctx->buf == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if ((ctx->idx + 5u) > ctx->bufSz) {
        ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
    }
    else {
        (void)XMEMCPY(&bits, &val, sizeof(bits));
        ctx->buf[ctx->idx] = (uint8_t)((WOLFCOSE_CBOR_SIMPLE << 5) |
                                         WOLFCOSE_CBOR_AI_FLOAT32);
        WOLFCOSE_STORE_BE32(&ctx->buf[ctx->idx + 1u], bits);
        ctx->idx += 5u;
        ret = WOLFCOSE_SUCCESS;
    }
    return ret;
}

int wc_CBOR_EncodeDouble(WOLFCOSE_CBOR_CTX* ctx, double val)
{
    int ret;
    uint64_t bits;

    if ((ctx == NULL) || (ctx->buf == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if ((ctx->idx + 9u) > ctx->bufSz) {
        ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
    }
    else {
        (void)XMEMCPY(&bits, &val, sizeof(bits));
        ctx->buf[ctx->idx] = (uint8_t)((WOLFCOSE_CBOR_SIMPLE << 5) |
                                         WOLFCOSE_CBOR_AI_FLOAT64);
        WOLFCOSE_STORE_BE64(&ctx->buf[ctx->idx + 1u], bits);
        ctx->idx += 9u;
        ret = WOLFCOSE_SUCCESS;
    }
    return ret;
}
#endif /* WOLFCOSE_FLOAT */

#endif /* WOLFCOSE_CBOR_ENCODE */

/* -----
 * Public Decode API
 *
 * Guarded by WOLFCOSE_CBOR_DECODE — always needed for verify/decrypt builds.
 * ----- */

#if defined(WOLFCOSE_CBOR_DECODE)

int wc_CBOR_DecodeHead(WOLFCOSE_CBOR_CTX* ctx, WOLFCOSE_CBOR_ITEM* item)
{
    return wolfCose_CBOR_DecodeHead(ctx, item);
}

int wc_CBOR_DecodeUint(WOLFCOSE_CBOR_CTX* ctx, uint64_t* val)
{
    int ret;
    WOLFCOSE_CBOR_ITEM item;

    if ((ctx == NULL) || (val == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        ret = wolfCose_CBOR_DecodeHead(ctx, &item);
        if (ret == WOLFCOSE_SUCCESS) {
            if (item.majorType != WOLFCOSE_CBOR_UINT) {
                ret = WOLFCOSE_E_CBOR_TYPE;
            }
            else {
                *val = item.val;
            }
        }
    }
    return ret;
}

int wc_CBOR_DecodeInt(WOLFCOSE_CBOR_CTX* ctx, int64_t* val)
{
    int ret;
    WOLFCOSE_CBOR_ITEM item;

    if ((ctx == NULL) || (val == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        ret = wolfCose_CBOR_DecodeHead(ctx, &item);
        if (ret == WOLFCOSE_SUCCESS) {
            if (item.majorType == WOLFCOSE_CBOR_UINT) {
                if (item.val > (uint64_t)INT64_MAX) {
                    ret = WOLFCOSE_E_CBOR_OVERFLOW;
                }
                else {
                    *val = (int64_t)item.val;
                }
            }
            else if (item.majorType == WOLFCOSE_CBOR_NEGINT) {
                /* RFC 8949: value = -1 - val */
                if (item.val > (uint64_t)INT64_MAX) {
                    ret = WOLFCOSE_E_CBOR_OVERFLOW;
                }
                else {
                    *val = -1 - (int64_t)item.val;
                }
            }
            else {
                ret = WOLFCOSE_E_CBOR_TYPE;
            }
        }
    }
    return ret;
}

/* Shared decode for bstr (major type 2) and tstr (major type 3) */
static int wolfCose_CBOR_DecodeBytes(WOLFCOSE_CBOR_CTX* ctx,
                                       uint8_t majorType,
                                       const uint8_t** data, size_t* dataLen)
{
    int ret;
    WOLFCOSE_CBOR_ITEM item;

    if ((ctx == NULL) || (data == NULL) || (dataLen == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        ret = wolfCose_CBOR_DecodeHead(ctx, &item);
        if (ret == WOLFCOSE_SUCCESS) {
            if (item.majorType != majorType) {
                ret = WOLFCOSE_E_CBOR_TYPE;
            }
            else {
                *data = item.data;
                *dataLen = item.dataLen;
            }
        }
    }
    return ret;
}

int wc_CBOR_DecodeBstr(WOLFCOSE_CBOR_CTX* ctx, const uint8_t** data,
                        size_t* dataLen)
{
    return wolfCose_CBOR_DecodeBytes(ctx, WOLFCOSE_CBOR_BSTR, data, dataLen);
}

int wc_CBOR_DecodeTstr(WOLFCOSE_CBOR_CTX* ctx, const uint8_t** str,
                        size_t* strLen)
{
    return wolfCose_CBOR_DecodeBytes(ctx, WOLFCOSE_CBOR_TSTR, str, strLen);
}

/* Shared decode for array (major type 4) and map (major type 5) */
static int wolfCose_CBOR_DecodeContainerStart(WOLFCOSE_CBOR_CTX* ctx,
                                                uint8_t majorType,
                                                size_t* count)
{
    int ret;
    WOLFCOSE_CBOR_ITEM item;

    if ((ctx == NULL) || (count == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        ret = wolfCose_CBOR_DecodeHead(ctx, &item);
        if (ret == WOLFCOSE_SUCCESS) {
            if (item.majorType != majorType) {
                ret = WOLFCOSE_E_CBOR_TYPE;
            }
            else {
                *count = (size_t)item.val;
            }
        }
    }
    return ret;
}

int wc_CBOR_DecodeArrayStart(WOLFCOSE_CBOR_CTX* ctx, size_t* count)
{
    return wolfCose_CBOR_DecodeContainerStart(ctx, WOLFCOSE_CBOR_ARRAY, count);
}

int wc_CBOR_DecodeMapStart(WOLFCOSE_CBOR_CTX* ctx, size_t* count)
{
    return wolfCose_CBOR_DecodeContainerStart(ctx, WOLFCOSE_CBOR_MAP, count);
}

int wc_CBOR_DecodeTag(WOLFCOSE_CBOR_CTX* ctx, uint64_t* tag)
{
    int ret;
    WOLFCOSE_CBOR_ITEM item;

    if ((ctx == NULL) || (tag == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        ret = wolfCose_CBOR_DecodeHead(ctx, &item);
        if (ret == WOLFCOSE_SUCCESS) {
            if (item.majorType != WOLFCOSE_CBOR_TAG) {
                ret = WOLFCOSE_E_CBOR_TYPE;
            }
            else {
                *tag = item.val;
            }
        }
    }
    return ret;
}

/* -----
 * wc_CBOR_Skip: iterative traversal to skip a complete CBOR item.
 * Uses a bounded stack (no recursion, MISRA Rule 17.2 compliant).
 * ----- */
int wc_CBOR_Skip(WOLFCOSE_CBOR_CTX* ctx)
{
    int ret;
    WOLFCOSE_CBOR_ITEM item;
    /* Stack of remaining items to skip at each nesting level */
    size_t stack[WOLFCOSE_CBOR_MAX_DEPTH];

    if (ctx == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        unsigned int depth = 0u;
        size_t remaining = 1; /* Start: need to skip 1 item */
        ret = WOLFCOSE_SUCCESS;

        while ((remaining > 0u) && (ret == WOLFCOSE_SUCCESS)) {
            ret = wolfCose_CBOR_DecodeHead(ctx, &item);
            if (ret != WOLFCOSE_SUCCESS) {
                break;
            }

            remaining--;

            if (item.majorType == WOLFCOSE_CBOR_ARRAY) {
                if (item.val > 0u) {
                    if (depth >= WOLFCOSE_CBOR_MAX_DEPTH) {
                        ret = WOLFCOSE_E_CBOR_DEPTH;
                    }
                    else if (item.val > ctx->bufSz) {
                        /* Sanitize: can't have more items than bytes */
                        ret = WOLFCOSE_E_CBOR_MALFORMED;
                    }
                    else {
                        stack[depth] = remaining;
                        depth++;
                        remaining = (size_t)item.val;
                    }
                }
            }
            else if (item.majorType == WOLFCOSE_CBOR_MAP) {
                if (item.val > 0u) {
                    if (depth >= WOLFCOSE_CBOR_MAX_DEPTH) {
                        ret = WOLFCOSE_E_CBOR_DEPTH;
                    }
                    else if (item.val > ctx->bufSz) {
                        /* Sanitize: can't have more entries than bytes */
                        ret = WOLFCOSE_E_CBOR_MALFORMED;
                    }
                    else if (item.val > (SIZE_MAX / 2u)) {
                        /* Prevent overflow in item.val * 2 */
                        ret = WOLFCOSE_E_CBOR_MALFORMED;
                    }
                    else {
                        stack[depth] = remaining;
                        depth++;
                        /* Each map entry is key + value = 2 items per pair */
                        remaining = (size_t)(item.val * 2u);
                    }
                }
            }
            else if (item.majorType == WOLFCOSE_CBOR_TAG) {
                /* Tag wraps exactly one item */
                remaining++;
            }
            else {
                /* For uint/negint/bstr/tstr/simple: already consumed by DecodeHead */
            }

            /* Unwind stack when current level is exhausted */
            while ((remaining == 0u) && (depth > 0)) {
                depth--;
                remaining = stack[depth];
            }
        }
    }
    return ret;
}

#endif /* WOLFCOSE_CBOR_DECODE */
