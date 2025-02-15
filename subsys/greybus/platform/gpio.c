/*
 * Copyright (c) 2020 Friedt Professional Engineering Services, Inc
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <zephyr/drivers/gpio.h>
#include <dt-bindings/greybus/greybus.h>
#include <greybus/greybus.h>
#include <greybus/platform.h>
#include <stdint.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/kernel.h>

#define DT_DRV_COMPAT zephyr_greybus_gpio_controller
#include <zephyr/device.h>

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(greybus_platform_gpio_control, CONFIG_GREYBUS_LOG_LEVEL);

#include "../gpio-gb.h"
#include "transport.h"

struct greybus_gpio_control_config {
	const uint8_t id;
	const uint8_t bundle;
	const struct device *greybus_gpio_controller;
	const char *const bus_name;
};

struct greybus_gpio_control_data {
	const struct device *greybus_gpio_controller;
	struct gpio_callback callback;
};

static void gpio_callback_handler(const struct device *port, struct gpio_callback *cb,
				  gpio_port_pins_t pins)
{
	/*
	 * Note: Currently, the greybus subsystem sends IRQ events
	 * kind of excessively, because there is no way to query
	 * the gpio subsystem for current pin configuration.
	 * Greybus irq events should naturally only be generated
	 * for input pins for example, and more specifically,
	 * input pins that are configured to generate interrupts!
	 * So we need to filter-out irq messages here until
	 * the expected message comes through :(
	 *
	 * See https://github.com/zephyrproject-rtos/zephyr/issues/26938
	 */

	int r;
	const struct gb_transport_backend *xport;
	unsigned int cport;
	uint8_t req_[0 + sizeof(struct gb_operation_hdr) +
		     sizeof(struct gb_gpio_irq_event_request)] = {};
	struct gb_operation_hdr *const req = (struct gb_operation_hdr *)req_;
	struct gb_gpio_irq_event_request *const irq_event_req =
		(struct gb_gpio_irq_event_request *)(req_ + sizeof(struct gb_operation_hdr));

	req->size = sys_cpu_to_le16(sizeof(req_));
	req->type = GB_GPIO_TYPE_IRQ_EVENT;

	xport = gb_transport_get_backend();
	__ASSERT(xport != NULL, "unable to get greybus transport backend");

	cport = gb_device_to_cport(port);
	__ASSERT(cport >= 0, "unabled to get cport binding for device %p", port);

	for (size_t i = 0; i < GPIO_MAX_PINS_PER_PORT && pins != 0; ++i, pins >>= 1) {
		if (pins & 1) {
			irq_event_req->which = i;
			r = xport->send(cport, req_, sizeof(req_));
			if (r != 0) {
				LOG_ERR("xport->send() failed: %d", r);
			}
		}
	}
}

static int greybus_gpio_control_init(const struct device *dev)
{

	struct greybus_gpio_control_data *drv_data = (struct greybus_gpio_control_data *)dev->data;
	struct greybus_gpio_control_config *config =
		(struct greybus_gpio_control_config *)dev->config;
	int r;
	const struct device *bus;
	gpio_port_pins_t mask;

	drv_data->greybus_gpio_controller = config->greybus_gpio_controller;
	if (NULL == drv_data->greybus_gpio_controller) {
		return -ENODEV;
	}

	mask = ((struct gpio_driver_config *)drv_data->greybus_gpio_controller->config)
		       ->port_pin_mask;

	bus = device_get_binding(config->bus_name);
	if (NULL == bus) {
		LOG_ERR("gpio control: failed to get binding for device '%s'", config->bus_name);
		return -ENODEV;
	}

	r = gb_add_cport_device_mapping(config->id, drv_data->greybus_gpio_controller);
	if (r < 0) {
		LOG_ERR("gpio control: failed to add mapping between %u and %s", config->id,
			dev->name);
		return r;
	}

	drv_data->callback.handler = gpio_callback_handler;
	drv_data->callback.pin_mask = mask;
	r = gpio_add_callback(drv_data->greybus_gpio_controller, &drv_data->callback);
	if (r < 0) {
		LOG_ERR("gpio_add_callback() failed for cport %u", config->id);
		return r;
	}

	LOG_DBG("probed cport %u: bundle: %u protocol: %u", config->id, config->bundle,
		CPORT_PROTOCOL_GPIO);

	return 0;
}

#define DEFINE_GREYBUS_GPIO_CONTROL(_num)                                                          \
                                                                                                   \
	BUILD_ASSERT(DT_PROP(DT_PARENT(DT_DRV_INST(_num)), bundle_class) ==                        \
			     BUNDLE_CLASS_BRIDGED_PHY,                                             \
		     "BUNDLE_CLASS_BRIDGED_PHY required");                                         \
                                                                                                   \
	BUILD_ASSERT(DT_PROP(DT_DRV_INST(_num), cport_protocol) == CPORT_PROTOCOL_GPIO,            \
		     "CPORT_PROTOCOL_GPIO required");                                              \
                                                                                                   \
	static struct greybus_gpio_control_config greybus_gpio_control_config_##_num = {           \
		.id = (uint8_t)DT_INST_PROP(_num, id),                                             \
		.bundle = (uint8_t)DT_PROP(DT_PARENT(DT_DRV_INST(_num)), id),                      \
		.greybus_gpio_controller =                                                         \
			DEVICE_DT_GET(DT_PHANDLE(DT_DRV_INST(_num), greybus_gpio_controller)),     \
		.bus_name = DT_NODE_FULL_NAME(DT_PARENT(DT_PARENT(DT_DRV_INST(_num)))),            \
	};                                                                                         \
                                                                                                   \
	static struct greybus_gpio_control_data greybus_gpio_control_data_##_num;                  \
                                                                                                   \
	DEVICE_DT_INST_DEFINE(_num, greybus_gpio_control_init, NULL,                               \
			      &greybus_gpio_control_data_##_num,                                   \
			      &greybus_gpio_control_config_##_num, POST_KERNEL,                    \
			      CONFIG_GREYBUS_CPORT_INIT_PRIORITY, NULL);

DT_INST_FOREACH_STATUS_OKAY(DEFINE_GREYBUS_GPIO_CONTROL);
