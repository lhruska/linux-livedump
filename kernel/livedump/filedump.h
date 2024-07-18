/* SPDX-License-Identifier: GPL-2.0-or-later */
/* filedump.h - Live Dump's filesystem dumping management
 * Copyright (C) 2024 SUSE
 * Author: Lukas Hruska <lhruska@suse.cz>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef _LIVEDUMP_FILEDUMP_H
#define _LIVEDUMP_FILEDUMP_H

#include "core.h"

extern struct livedump_handler filedump_handler;

extern int livedump_filedump_init(struct livedump_shared data);

extern void livedump_filedump_uninit(bool forced);

extern void livedump_filedump_sm_init(void);

extern void livedump_filedump_write_elf_hdr(void);

#endif /* _LIVEDUMP_FILEDUMP_H */
