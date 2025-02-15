/*
 * Copyright (c) 2020 Friedt Professional Engineering Services, Inc
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdint.h>
#include <zephyr/kernel.h>

#define DT_DRV_COMPAT zephyr_greybus
#include <zephyr/device.h>

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(greybus_platform_bus, CONFIG_GREYBUS_LOG_LEVEL);

struct greybus_config {
	const uint8_t id;
	const uint8_t version_major;
	const uint8_t version_minor;
};

static int greybus_init(const struct device *bus)
{

	const struct greybus_config *const config = (const struct greybus_config *)bus->config;

	LOG_DBG("probed greybus: %u major: %u minor: %u", config->id, config->version_major,
		config->version_minor);

	return 0;
}

#define DEFINE_GREYBUS(_num)                                                                       \
                                                                                                   \
	static const struct greybus_config greybus_config_##_num = {                               \
		.id = _num,                                                                        \
		.version_major = DT_INST_PROP(_num, version_major),                                \
		.version_minor = DT_INST_PROP(_num, version_minor),                                \
	};                                                                                         \
                                                                                                   \
	DEVICE_DT_INST_DEFINE(_num, greybus_init, NULL, NULL, &greybus_config_##_num, POST_KERNEL, \
			      CONFIG_GREYBUS_SERVICE_INIT_PRIORITY, NULL);

DT_INST_FOREACH_STATUS_OKAY(DEFINE_GREYBUS);
