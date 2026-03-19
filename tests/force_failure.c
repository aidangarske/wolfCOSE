/* force_failure.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
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
