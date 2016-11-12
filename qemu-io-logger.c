#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include "config.h"
#include "exec/memory.h"
#include "qemu-common.h"
#include "qemu/log.h"
#include "qemu/io-logger.h"
#include "exec/address-spaces.h"

static char *io_logfilename;
FILE *qemu_io_logfile;

#define SOCKET_PATH "/tmp/socket.sock"
#define BUF_SIZE 4096
static int sock = -1;
static struct sockaddr_un sockaddr;
static char str_buf[BUF_SIZE] = {'\0'};

static unsigned int log_index = 0;

char *int2binstr(uint32_t val, char *buffer, int buf_size);
char *int2binstr(uint32_t val, char *buffer, int buf_size)
{
  char buf[buf_size];
  char *hp;
  uint32_t v = val;
  int size = 0;
  int cnt = 0;
  buf[buf_size - 1] = '\0';
  for (hp = &buf[buf_size - 2]; hp > buf && cnt < 32; hp--, cnt++) {
    if (cnt != 0 && cnt % 4 == 0) {
      *hp-- = ' ';
    }
    *hp = (v & 0x1) ? '1' : '0';

    size++;
    v >>= 1;
    if (v == 0) {
      break;
    }
  }
  strncpy(buffer, hp, buf_size);
  return buffer;
}

void qemu_nic_log_bin_str(const char *msg, uint32_t val)
{
  char buf[BUF_SIZE];
  int2binstr(val, buf, BUF_SIZE);
  qemu_nic_log_fmt("%s [%s]", msg, buf);
}

void qemu_nic_log_fmt(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(str_buf, BUF_SIZE, fmt, ap);
  va_end(ap);
  qemu_nic_log(str_buf);
}

void qemu_nic_log(const char *msg)
{
  if (qemu_io_logfile) {
    fprintf(qemu_io_logfile, "%u: [nic] %s\n", log_index, msg);
    fflush(qemu_io_logfile);
  }
  log_index++;
}

void qemu_nic_log_line_break(void)
{
  if (qemu_io_logfile) {
    fprintf(qemu_io_logfile, "\n");
  }
}

void qemu_nic_simple_log(const char *msg)
{
  if (qemu_io_logfile) {
    fprintf(qemu_io_logfile, "%s\n", msg);
    fflush(qemu_io_logfile);
  }
}

static void qemu_io_log(const char *fmt, ...)
{
  return;
  if (sock < 0) {
    return;
  }

  va_list ap;
  va_start(ap, fmt);
  vsnprintf(str_buf, BUF_SIZE, fmt, ap);
  va_end(ap);

  //fprintf(stderr, "> qemu_io_log\n");
  if (qemu_io_logfile) {
    fprintf(qemu_io_logfile, "%s", str_buf);
  }
  if (write(sock, str_buf, strnlen(str_buf, BUF_SIZE)) < 0) {
    fprintf(stderr, "hogehoge\n");
    perror("write");
    exit(-1);
  }
  if (read(sock, str_buf, 10) <= 0) {
    perror("read");
    exit(-1);
  }

  if (strncmp(str_buf, "ACK", 10) == 0) {
    //printf("ACCEPTED! [%u] %s\n", (unsigned int) strnlen(str_buf, 10), str_buf);
  } else {
    //printf("NOT ACCEPTED... [%u] %s\n", (unsigned int)strnlen(str_buf, 10), str_buf);
  }
}

static inline void qemu_log_parse_msr_value(uint64_t msr, char *buf, unsigned int len)
{
  int cur_len = 1;
  buf[0] = '[';
  buf[1] = '\0';

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

inline void qemu_io_port_log(bool is_write, hwaddr port_addr, uint64_t val) {
  if (0x03F0 <= port_addr && port_addr != 0x03F6 && port_addr <= 0x03F7) {
    char status[1024];
    status[0] = '\0';
    if (!is_write && port_addr == 0x03F4) qemu_log_parse_msr_value(val, status, 1024);

    qemu_io_log("[io] %c 0x%04x 0x%x %s\n", (is_write ? 'w' : 'r'),
        (unsigned int) port_addr, (unsigned int)val, status);
  }
}

inline void qemu_irq_log(int irq_no, int level)
{
  if (irq_no == QEMU_FDC_IRQ_NO) {
    qemu_io_log("[io] i %d %d\n", irq_no, level);
  }
}

inline void qemu_dma_log(const char *buf)
{
  qemu_io_log(buf);
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

  sock = socket(AF_UNIX, SOCK_STREAM, 0);

  if (sock < 0) {
    perror("cannot open socket");
    _exit(1);
  }

  memset(&sockaddr, 0, sizeof(struct sockaddr_un));
  sockaddr.sun_family = AF_UNIX;
  strcpy(sockaddr.sun_path, SOCKET_PATH);

  if (connect(sock, (struct sockaddr *)&sockaddr, sizeof(struct sockaddr_un)) < 0) {
    perror("cannot connect to socket");
    sock = -1;
    return;
  }
}
