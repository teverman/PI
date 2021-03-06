/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#ifndef PI_SRC_P4INFO_P4INFO_NAME_MAP_H_
#define PI_SRC_P4INFO_P4INFO_NAME_MAP_H_

#include <PI/pi_base.h>

typedef void *p4info_name_map_t;

void p4info_name_map_add(p4info_name_map_t *map, const char *name,
                         pi_p4_id_t id);

pi_p4_id_t p4info_name_map_get(const p4info_name_map_t *map, const char *name);

void p4info_name_map_destroy(p4info_name_map_t *map);

#endif  // PI_SRC_P4INFO_P4INFO_NAME_MAP_H_
