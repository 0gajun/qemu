#include <string.h>
#include "config.h"
#include "exec/memory.h"
#include "qemu-common.h"
#include "qemu/log.h"
#include "qemu/io-logger.h"
#include "exec/address-spaces.h"

static char *io_logfilename;
FILE *qemu_io_logfile;

static void qemu_io_log(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    if (qemu_io_logfile) {
      vfprintf(qemu_io_logfile, fmt, ap);
      fflush(qemu_io_logfile);
    }
    va_end(ap);
}

static void qemu_log_parse_msr_value(uint64_t msr, char *buf, unsigned int len)
{
  int cur_len = 1;
  buf[0] = '\0';

  snprintf(buf, len, "0x%x [", (unsigned int)msr);
  cur_len = strnlen(buf, len);

  if (msr & MSR_RQM) {
    strncat(buf, "RQM ", len - cur_len);
    cur_len += 4;
  }
  if (msr & MSR_DIO) {
    strncat(buf, "DIO ", len - cur_len);
    cur_len += 4;
  }
  if (msr & MSR_NON_DMA) {
    strncat(buf, "NON_DMA ", len - cur_len);
    cur_len += 8;
  }
  if (msr & MSR_CMD_BSY) {
    strncat(buf, "CMD_BSY ", len - cur_len);
    cur_len += 8;
  }
  if (msr & MSR_DRV0_BSY) {
    strncat(buf, "DRV0_BSY ", len - cur_len);
    cur_len += 9;
  }
  if (msr & MSR_DRV1_BSY) {
    strncat(buf, "DRV1_BSY ", len - cur_len);
    cur_len += 9;
  }
  if (msr & MSR_DRV2_BSY) {
    strncat(buf, "DRV2_BSY ", len - cur_len);
    cur_len += 9;
  }
  if (msr & MSR_DRV3_BSY) {
    strncat(buf, "DRV3_BSY ", len - cur_len);
    cur_len += 9;
  }
  strncat(buf, "]", len - cur_len);
}

void qemu_io_port_log(bool is_write, hwaddr port_addr, uint64_t val) {
    if (0x03F0 <= port_addr && port_addr != 0x03F6 && port_addr <= 0x03F7) {
      char status[1024];
      status[0] = '\0';
      if (!is_write && port_addr == 0x03F4) qemu_log_parse_msr_value(val, status, 1024);

      qemu_io_log("[io] %c 0x%04x 0x%x %s\n", (is_write ? 'w' : 'r'), (unsigned int) port_addr, (unsigned int)val, status);

      /*
      if (is_write) {
          qemu_io_log("[io] w 0x%04x 0x%x %s\n", (unsigned int) port_addr, (unsigned int)val, status);
      } else {
          qemu_io_log("[io] r 0x%04x 0x%x %s\n", (unsigned int) port_addr, (unsigned int)val, status);
      }
      */
    }
}

void qemu_irq_log(int irq_no, int level)
{
    if (irq_no == QEMU_FDC_IRQ_NO) {
      qemu_io_log("[io] i %d %d\n", irq_no, level);
    }
}

void qemu_set_io_log_filename(const char *filename)
{
    g_free(io_logfilename);
    io_logfilename = g_strdup(filename);
    qemu_io_log_close();
    if (io_logfilename && !qemu_io_logfile) {
      qemu_io_logfile = fopen(io_logfilename, "w");
      if (!qemu_io_logfile) {
        perror(io_logfilename);
        _exit(1);
      }
    }
}
