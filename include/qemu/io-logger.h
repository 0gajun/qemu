#ifndef QEMU_IO_LOGGER_H
#define QEMU_IO_LOGGER_H

#include "hw/block/fdc.h"

#define QEMU_FDC_IRQ_NO 6

#define MAIN_STATUS_REGISTER 0x3F4
#define MSR_RQM 0x80
#define MSR_DIO 0x40
#define MSR_NON_DMA 0x20
#define MSR_CMD_BSY 0x10
#define MSR_DRV3_BSY 0x08
#define MSR_DRV2_BSY 0x04
#define MSR_DRV1_BSY 0x02
#define MSR_DRV0_BSY 0x01

extern FILE *qemu_io_logfile;

void qemu_io_port_log(bool is_write, hwaddr port_addr, uint64_t val);
void qemu_irq_log(int irq_no, int level);
void qemu_dma_log(const char *buf);

void qemu_set_io_log_filename(const char *filename);

static inline void qemu_io_log_close(void)
{
  if (qemu_io_logfile) {
    fclose(qemu_io_logfile);
    qemu_io_logfile = NULL;
  }
}

#endif
