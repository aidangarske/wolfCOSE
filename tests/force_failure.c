/* force_failure.c
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
 *
 * Implementation of forced failure injection for coverage testing.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#ifdef WOLFCOSE_FORCE_FAILURE

#include "force_failure.h"

/* Global failure state - which function should fail next */
static WolfForceFailure g_nextFailure = WOLF_FAIL_NONE;

void wolfForceFailure_Set(WolfForceFailure failure)
{
    g_nextFailure = failure;
}

WolfForceFailure wolfForceFailure_Get(void)
{
    return g_nextFailure;
}

void wolfForceFailure_Clear(void)
{
    g_nextFailure = WOLF_FAIL_NONE;
}

int wolfForceFailure_Check(WolfForceFailure failure)
{
    if (g_nextFailure == failure) {
        g_nextFailure = WOLF_FAIL_NONE;  /* Auto-reset after triggering */
        return 1;
    }
    return 0;
}

#endif /* WOLFCOSE_FORCE_FAILURE */
