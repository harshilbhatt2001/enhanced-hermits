/*
 * Copyright (c) 2020 Friedt Professional Engineering Services, Inc
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <zephyr/device.h>
#include <errno.h>
#include <greybus/platform.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <zephyr/kernel.h>

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(greybus_platform, CONFIG_GREYBUS_LOG_LEVEL);

struct map_entry {
	unsigned int cport;
	const struct device *dev;
};

static size_t map_size;
static struct map_entry *map;
K_MUTEX_DEFINE(map_mutex);

int gb_add_cport_device_mapping(unsigned int cport, const struct device *dev)
{
	int ret;
	int mutex_ret;
	size_t idx;
	struct map_entry *entry;

	if (dev == NULL) {
		return -EINVAL;
	}

	__ASSERT_NO_MSG(dev->name != NULL);

	mutex_ret = k_mutex_lock(&map_mutex, K_FOREVER);
	__ASSERT_NO_MSG(mutex_ret == 0);

	for (idx = 0; idx < map_size; ++idx) {
		entry = &map[idx];
		if (entry->cport == cport) {
			LOG_ERR("%u is already mapped to %s", cport, entry->dev->name);
			ret = -EALREADY;
			goto unlock;
		}
		if (entry->dev == dev) {
			LOG_ERR("%s is already mapped to %u", entry->dev->name, entry->cport);
			ret = -EALREADY;
			goto unlock;
		}
	}

	entry = realloc(map, (map_size + 1) * sizeof(*entry));
	if (entry == NULL) {
		ret = -ENOMEM;
		goto unlock;
	}

	map = entry;
	entry = &map[map_size];
	map_size++;

	entry->cport = cport;
	entry->dev = dev;

	LOG_DBG("added mapping between cport %u and device %s", cport, dev->name);

	ret = 0;

unlock:
	mutex_ret = k_mutex_unlock(&map_mutex);
	__ASSERT_NO_MSG(mutex_ret == 0);

	return ret;
}

int gb_device_to_cport(const struct device *dev)
{
	int ret;
	int mutex_ret;
	size_t idx;
	struct map_entry *entry;

	mutex_ret = k_mutex_lock(&map_mutex, K_FOREVER);
	__ASSERT_NO_MSG(mutex_ret == 0);

	for (idx = 0; idx < map_size; ++idx) {
		entry = &map[idx];
		if (entry->dev == dev) {
			ret = entry->cport;
			goto unlock;
		}
	}

	LOG_ERR("no mapping for device %s",
		(dev == NULL) ? "(null)" : ((dev->name == NULL) ? "(null)" : dev->name));
	ret = -ENOENT;

unlock:
	mutex_ret = k_mutex_unlock(&map_mutex);
	__ASSERT_NO_MSG(mutex_ret == 0);

	return ret;
}

const struct device *gb_cport_to_device(unsigned int cport)
{
	const struct device *ret;
	int mutex_ret;
	size_t idx;
	struct map_entry *entry;

	mutex_ret = k_mutex_lock(&map_mutex, K_FOREVER);
	__ASSERT_NO_MSG(mutex_ret == 0);

	for (idx = 0; idx < map_size; ++idx) {
		entry = &map[idx];
		if (entry->cport == cport) {
			ret = entry->dev;
			goto unlock;
		}
	}

	LOG_ERR("no mapping for cport %u", cport);
	ret = NULL;

unlock:
	mutex_ret = k_mutex_unlock(&map_mutex);
	__ASSERT_NO_MSG(mutex_ret == 0);

	return ret;
}
