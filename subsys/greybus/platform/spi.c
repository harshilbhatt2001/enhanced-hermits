/*
 * Copyright (c) 2020 Friedt Professional Engineering Services, Inc
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <zephyr/drivers/spi.h>
#include <dt-bindings/greybus/greybus.h>
#include <greybus/greybus.h>
#include <greybus/platform.h>
#include <stdint.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/kernel.h>

#define DT_DRV_COMPAT zephyr_greybus_spi_controller
#include <zephyr/device.h>

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(greybus_platform_spi_control, CONFIG_GREYBUS_LOG_LEVEL);

#include "../spi-gb.h"
#include "transport.h"

struct devpair {
	const struct device *a;
	const struct device *b;
};

static struct devpair *gb_spidev_pairs;
static size_t gb_num_spidev_pairs;
static K_SEM_DEFINE(gb_spidev_pairs_sem, 1, 1);

const struct device *gb_spidev_from_zephyr_spidev(const struct device *dev)
{
	int r;
	const struct device *ret;
	struct devpair *p;

	r = k_sem_take(&gb_spidev_pairs_sem, K_FOREVER);
	__ASSERT_NO_MSG(r == 0);

	for (size_t i = 0; i < gb_num_spidev_pairs; ++i) {
		p = &gb_spidev_pairs[i];
		if (p->a == dev) {
			ret = p->b;
			goto unlock;
		}
	}

	ret = NULL;
	LOG_ERR("no greybus spi device exists for physical device %p", dev);

unlock:
	k_sem_give(&gb_spidev_pairs_sem);

	return ret;
}

/**
 * Pair a greybus spi meta-device with a physical spi device
 *
 * @param a the greybus spi meta-device
 * @param b the physical spi device
 *
 * @return 0 on success
 * @return a negative errno value on failure
 */
static int gb_add_spipair(const struct device *a, const struct device *b)
{
	int r;
	struct devpair *p;

	if (a == NULL || b == NULL) {
		return -EINVAL;
	}

	r = k_sem_take(&gb_spidev_pairs_sem, K_FOREVER);
	__ASSERT_NO_MSG(r == 0);

	for (size_t i = 0; i < gb_num_spidev_pairs; ++i) {
		p = &gb_spidev_pairs[i];
		if (p->a == a || p->b == b) {
			r = -EALREADY;
			goto unlock;
		}
	}

	p = realloc(gb_spidev_pairs, (1 + gb_num_spidev_pairs) * sizeof(*p));
	if (p == NULL) {
		r = -ENOMEM;
		goto unlock;
	}

	gb_spidev_pairs = p;
	p = &gb_spidev_pairs[gb_num_spidev_pairs];
	p->a = a;
	p->b = b;
	gb_num_spidev_pairs++;

	LOG_DBG("added spi device mapping %p <-> %p", a, b);

unlock:
	k_sem_give(&gb_spidev_pairs_sem);

	return r;
}

struct greybus_spi_control_config {
	const uint8_t id;
	const uint8_t bundle;
	const struct device *greybus_spi_controller;
	const char *const bus_name;

	const struct gb_spi_master_config_response ctrl_rsp;
	const uint8_t num_peripherals;
	const struct gb_spi_device_config_response *periph_rsp;

	const struct spi_cs_control *cs_control;
	const uint8_t num_cs_control;
};

struct greybus_spi_control_data {
	const struct device *greybus_spi_controller;
};

static int greybus_spi_control_init(const struct device *dev)
{

	struct greybus_spi_control_data *drv_data = (struct greybus_spi_control_data *)dev->data;
	struct greybus_spi_control_config *config =
		(struct greybus_spi_control_config *)dev->config;
	int r;
	const struct device *bus;

	drv_data->greybus_spi_controller = config->greybus_spi_controller;
	if (NULL == drv_data->greybus_spi_controller) {
		return -ENODEV;
	}

	r = gb_add_spipair(drv_data->greybus_spi_controller, dev);
	__ASSERT(r == 0, "failed to add spi mapping: %p <-> %p", dev,
		 drv_data->greybus_spi_controller);

	bus = device_get_binding(config->bus_name);
	if (NULL == bus) {
		LOG_ERR("spi control: failed to get binding for device '%s'", config->bus_name);
		return -ENODEV;
	}

	r = gb_add_cport_device_mapping(config->id, drv_data->greybus_spi_controller);
	if (r < 0) {
		LOG_ERR("spi control: failed to add mapping between %u and %s", config->id,
			dev->name);
		return r;
	}

	LOG_DBG("probed cport %u: bundle: %u protocol: %u", config->id, config->bundle,
		CPORT_PROTOCOL_SPI);

	return 0;
}

static int gb_plat_api_controller_config_response(const struct device *dev,
						  struct gb_spi_master_config_response *rsp)
{
	if (dev == NULL || NULL == rsp) {
		return -EINVAL;
	}

	const struct greybus_spi_control_config *const config =
		(struct greybus_spi_control_config *)dev->config;

	memcpy(rsp, &config->ctrl_rsp, sizeof(*rsp));

	return 0;
}

static int gb_plat_api_num_peripherals(const struct device *dev)
{
	if (dev == NULL) {
		return -EINVAL;
	}

	const struct greybus_spi_control_config *const config =
		(struct greybus_spi_control_config *)dev->config;

	return config->num_peripherals;
}

static int gb_plat_api_peripheral_config_response(const struct device *dev, uint8_t chip_select,
						  struct gb_spi_device_config_response *rsp)
{
	if (dev == NULL || NULL == rsp) {
		return -EINVAL;
	}

	const struct greybus_spi_control_config *const config =
		(struct greybus_spi_control_config *)dev->config;

	if (chip_select >= config->num_peripherals) {
		return -EINVAL;
	}

	memcpy(rsp, &config->periph_rsp[chip_select], sizeof(*rsp));

	return 0;
}

static int gb_plat_api_get_cs_control(const struct device *dev, uint8_t chip_select,
				      struct spi_cs_control *ctrl)
{
	if (dev == NULL || NULL == ctrl) {
		return -EINVAL;
	}

	const struct greybus_spi_control_config *const config =
		(struct greybus_spi_control_config *)dev->config;

	if (chip_select >= config->num_peripherals) {
		return -EINVAL;
	}

	if (config->cs_control[chip_select].gpio.port == NULL) {
		LOG_ERR("failed to look up cs %u GPIO device", chip_select);
		return -ENODEV;
	}

	memcpy(ctrl, &config->cs_control[chip_select], sizeof(*ctrl));

	return 0;
}

static const struct gb_platform_spi_api gb_platform_spi_api = {
	.controller_config_response = gb_plat_api_controller_config_response,
	.num_peripherals = gb_plat_api_num_peripherals,
	.peripheral_config_response = gb_plat_api_peripheral_config_response,
	.get_cs_control = gb_plat_api_get_cs_control,
};

#define COUNT_GBSPIDEV_OKAY(node_id)                                                               \
	+DT_NODE_HAS_COMPAT_STATUS(node_id, zephyr_greybus_spi_peripheral, okay)

#define DEFINE_GREYBUS_CTRL_RESP(_num)                                                             \
	{                                                                                          \
		.bpw_mask = DT_INST_PROP(_num, bpw_mask),                                          \
		.min_speed_hz = DT_INST_PROP(_num, min_speed_hz),                                  \
		.max_speed_hz = DT_INST_PROP(_num, max_speed_hz),                                  \
		.max_speed_hz = DT_INST_PROP(_num, max_speed_hz),                                  \
		.mode = DT_INST_PROP(_num, mode), .flags = DT_INST_PROP(_num, flags),              \
		.num_chipselect = DT_FOREACH_CHILD(DT_DRV_INST(_num), COUNT_GBSPIDEV_OKAY),        \
	}

#define DEFINE_GREYBUS_PERIPH_RSP(node_id)                                                         \
	[DT_PROP(node_id, cs)] = {                                                                 \
		.mode = DT_PROP(node_id, mode),                                                    \
		.bpw = DT_PROP(node_id, bpw),                                                      \
		.max_speed_hz = DT_PROP(node_id, max_speed_hz),                                    \
		.device_type = DT_PROP(node_id, device_type),                                      \
		.name = DT_PROP(node_id, device_name),                                             \
	},

#define SPIBUS(_node) DT_PHANDLE(DT_PARENT(_node), greybus_spi_controller)

#define SPIBUS_GPIO_LABEL(_spi, _cs)                                                               \
	((struct device *)(DT_SPI_HAS_CS_GPIOS(_spi) ? DT_GPIO_LABEL_BY_IDX(_spi, cs_gpios, _cs)   \
						     : NULL))

#define SPIBUS_GPIO_PIN(_spi, _cs)                                                                 \
	DT_SPI_HAS_CS_GPIOS(_spi) ? DT_GPIO_PIN_BY_IDX(_spi, cs_gpios, _cs) : -1

#define SPIBUS_GPIO_FLAGS(_spi, _cs)                                                               \
	DT_SPI_HAS_CS_GPIOS(_spi) ? DT_GPIO_FLAGS_BY_IDX(_spi, cs_gpios, _cs) : -1

#define DEFINE_CS_CTRL(node_id)                                                                    \
	[DT_PROP(node_id, cs)] = {                                                                 \
		.gpio_dev = SPIBUS_GPIO_LABEL(SPIBUS(node_id), DT_PROP(node_id, cs)),              \
		.delay = 0,                                                                        \
		.gpio_pin = SPIBUS_GPIO_PIN(SPIBUS(node_id), DT_PROP(node_id, cs)),                \
		.gpio_dt_flags = SPIBUS_GPIO_FLAGS(SPIBUS(node_id), DT_PROP(node_id, cs)),         \
	},

#define DEFINE_GREYBUS_SPI_CONTROL(_num)                                                           \
                                                                                                   \
	BUILD_ASSERT(DT_PROP(DT_PARENT(DT_DRV_INST(_num)), bundle_class) ==                        \
			     BUNDLE_CLASS_BRIDGED_PHY,                                             \
		     "BUNDLE_CLASS_BRIDGED_PHY required");                                         \
                                                                                                   \
	BUILD_ASSERT(DT_PROP(DT_DRV_INST(_num), cport_protocol) == CPORT_PROTOCOL_SPI,             \
		     "CPORT_PROTOCOL_SPI required");                                               \
                                                                                                   \
	static const struct gb_spi_device_config_response periph_rsp_##_num[] = {                  \
		DT_FOREACH_CHILD(DT_DRV_INST(_num), DEFINE_GREYBUS_PERIPH_RSP)};                   \
	static const struct spi_cs_control cs_control_##_num[] = {                                 \
		DT_FOREACH_CHILD(DT_DRV_INST(_num), DEFINE_CS_CTRL)};                              \
                                                                                                   \
	static const struct greybus_spi_control_config greybus_spi_control_config_##_num = {       \
		.id = (uint8_t)DT_INST_PROP(_num, id),                                             \
		.bundle = (uint8_t)DT_PROP(DT_PARENT(DT_DRV_INST(_num)), id),                      \
		.greybus_spi_controller =                                                          \
			DEVICE_DT_GET(DT_PHANDLE(DT_DRV_INST(_num), greybus_spi_controller)),      \
		.bus_name = DT_LABEL(DT_PARENT(DT_PARENT(DT_DRV_INST(_num)))),                     \
		.ctrl_rsp = DEFINE_GREYBUS_CTRL_RESP(_num),                                        \
		.num_peripherals = ARRAY_SIZE(periph_rsp_##_num),                                  \
		.periph_rsp = periph_rsp_##_num,                                                   \
		.cs_control = cs_control_##_num,                                                   \
	};                                                                                         \
                                                                                                   \
	static struct greybus_spi_control_data greybus_spi_control_data_##_num;                    \
                                                                                                   \
	DEVICE_DT_INST_DEFINE(_num, greybus_spi_control_init, NULL,                                \
			      &greybus_spi_control_data_##_num,                                    \
			      &greybus_spi_control_config_##_num, POST_KERNEL,                     \
			      CONFIG_GREYBUS_CPORT_INIT_PRIORITY, &gb_platform_spi_api);

DT_INST_FOREACH_STATUS_OKAY(DEFINE_GREYBUS_SPI_CONTROL);
