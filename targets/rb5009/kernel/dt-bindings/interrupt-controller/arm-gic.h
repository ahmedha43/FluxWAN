/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _DT_BINDINGS_INTERRUPT_CONTROLLER_ARM_GIC_H
#define _DT_BINDINGS_INTERRUPT_CONTROLLER_ARM_GIC_H
#include "irq.h"
#define GIC_SPI 0
#define GIC_PPI 1
#define GIC_CPU_MASK_SIMPLE(c) ((1 << (c)) - 1)
#endif
