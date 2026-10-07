/*
 * Improv Wi-Fi over the USB serial port (https://www.improv-wifi.com/serial/), so a browser
 * flasher (ESP Web Tools) can hand a new node its Wi-Fi network right after flashing. Runs
 * only when the node is on Wi-Fi. Packets share the port with the log output, as in the spec.
 */
#pragma once

void improv_start(void);
