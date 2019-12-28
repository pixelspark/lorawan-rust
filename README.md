# LoRaWAN 

A LoRaWAN stack for the RFM9x LoRa/FSK transceiver module for use on Raspberry Pi (work in progress).

Author: Tommy van der Vorst (Pixelspark)

## What works

Transmission of LoRA frames was successfully tested against The Things Network. Receiving currently does not work. Only ABP (activation by personalisation) is supported (this means that network/app session keys should be set in the device, and cannot be configured dynamically by the network, e.g. using OTAA).

Currently uses the `rfm9x` crate which only works on Raspberry Pi.

## Usage

See [the basic example](./examples/basic.rs).

## Copyright & license

Copyright (C) 2019-2020 Tommy van der Vorst, Pixelspark. Released under the  [MIT license](./LICENSE).

