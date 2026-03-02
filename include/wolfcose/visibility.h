/* visibility.h
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

#ifndef WOLFCOSE_VISIBILITY_H
#define WOLFCOSE_VISIBILITY_H

/* WOLFCOSE_API: marks symbols exported from the shared library.
 * WOLFCOSE_LOCAL: marks symbols hidden (internal linkage in shared builds). */

#if defined(_WIN32) || defined(__CYGWIN__)
    #ifdef BUILDING_WOLFCOSE
        #define WOLFCOSE_API __declspec(dllexport)
    #else
        #define WOLFCOSE_API __declspec(dllimport)
    #endif
    #define WOLFCOSE_LOCAL
#elif defined(__GNUC__) && (__GNUC__ >= 4)
    #ifdef BUILDING_WOLFCOSE
        #define WOLFCOSE_API __attribute__((visibility("default")))
    #else
        #define WOLFCOSE_API
    #endif
    #define WOLFCOSE_LOCAL __attribute__((visibility("hidden")))
#else
    #define WOLFCOSE_API
    #define WOLFCOSE_LOCAL
#endif

#endif /* WOLFCOSE_VISIBILITY_H */
