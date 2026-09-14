/*
 * tdts-dpi-dump -- dump the DPI application/category tables of the Trend
 * Micro TDTS engine (tdts.ko) via /dev/detector, and optionally regenerate
 * EdgeOS rule.xml / cats.xml from the loaded signature.
 *
 * The ioctl interface follows the vendor header (tdts_shell_ioctl.h, from
 * a BCM BSP); usage mirrors the reverse-engineered tdts_rule_agent
 * (github.com/novag/tdts_rule_agent): one _IOW(0xBE, 2, ...) request per
 * call, operation selected by the struct's op byte, kernel copies the reply
 * into our buffer and reports the used length.
 *
 * Output layouts, reverse-engineered from tdts.ko (ER-e50 v3.0.1):
 *   GET_SIG_VER      (3): u32[2]; major = v[0]>>16, minor = v[0]&0xffff, patch = v[1]
 *   GET_NR_CAT_NAME (12): out_len must be 2;  u16 = 32 (fixed slot count)
 *   GET_CAT_NAME     (13): 32 slots x 64 bytes each, name or all-zero if empty
 *   GET_NR_APP_NAME (16): out_len must be 2;  u16 app count
 *   GET_APP_NAME     (17): records of 67 bytes {u8 page, u16 idx, name[64]}
 *   GET_NR_APP_ID    (18): out_len must be 4;  u32 count of (page,idx,beh) combos
 *   GET_APP_DB       (19): records of 4 bytes {u8 page, u8 idx lo, u8 idx hi, u8 beh}
 *
 * The xml mode maps records positionally: cat_id = 128 + page, app_id = idx.
 * This mapping is an assumption -- validate once against the stock 1.564
 * signature (names must join with the shipped rule.xml/cats.xml) before
 * trusting regenerated files.  Categories the engine does not carry (e.g.
 * TopSites-*) will be absent from the output by design.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "tdts_shell_ioctl.h"

#define DEV_PATH     "/dev/detector"
#define CAT_SLOTS    32
#define CAT_SLOT_SZ  64
#define CAT_BUF_SZ   (CAT_SLOTS * CAT_SLOT_SZ)
#define APP_REC_SZ   67
#define APP_NAME_SZ  (APP_REC_SZ - 3)
#define APP_CAP_MAX  (4u << 20)

static int sig_op(int op, void *out, uint32_t out_len, uint32_t *used)
{
	tdts_shell_ioctl_t ioc;
	int fd, rc;

	memset(&ioc, 0, sizeof(ioc));
	ioc.magic = TDTS_SHELL_IOCTL_MAGIC;
	ioc.nr = TDTS_SHELL_IOCTL_NR_SIG;
	ioc.op = op;
	ioc.out = (uintptr_t)out;
	ioc.out_used_len = (uintptr_t)used;
	ioc.out_len = out_len;

	fd = open(DEV_PATH, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "open " DEV_PATH ": %s\n", strerror(errno));
		return -1;
	}
	rc = ioctl(fd, TDTS_SHELL_IOCTL_CMD_SIG, &ioc);
	close(fd);
	if (rc != 0) {
		fprintf(stderr, "ioctl op=%d: %s\n", op, strerror(errno));
		return -1;
	}
	return 0;
}

static int get_sig_ver(uint32_t *major, uint32_t *minor, uint32_t *patch)
{
	uint32_t ver[2] = { 0, 0 };
	uint32_t used = 0;

	if (sig_op(TDTS_SHELL_IOCTL_SIG_OP_GET_SIG_VER, ver, sizeof(ver), &used) != 0)
		return -1;
	*major = ver[0] >> 16;
	*minor = ver[0] & 0xffff;
	*patch = ver[1];
	return 0;
}

/* ops 12/16 answer with exactly one u16 and reject any other out_len */
static int get_nr_u16(int op, uint32_t *nr)
{
	uint16_t v = 0;
	uint32_t used = 0;

	if (sig_op(op, &v, sizeof(v), &used) != 0)
		return -1;
	*nr = v;
	return 0;
}

/* op 18 answers with one u32 and rejects any other out_len */
static int get_nr_u32(int op, uint32_t *nr)
{
	uint32_t v = 0;
	uint32_t used = 0;

	if (sig_op(op, &v, sizeof(v), &used) != 0)
		return -1;
	*nr = v;
	return 0;
}

static int get_cat_names(char cats[CAT_SLOTS][CAT_SLOT_SZ])
{
	uint32_t used = 0;

	memset(cats, 0, CAT_BUF_SZ);
	return sig_op(TDTS_SHELL_IOCTL_SIG_OP_GET_CAT_NAME, cats, CAT_BUF_SZ, &used);
}

/* collect fixed-size records; the kernel rejects undersized buffers with -1,
 * so grow and retry until it fits */
static int get_records(int op, uint32_t rec_sz, unsigned char **out, uint32_t *n_rec, uint32_t hint)
{
	uint32_t cap = (hint + 1) * rec_sz;
	uint32_t used = 0;

	if (cap < rec_sz)
		cap = rec_sz;
	if (cap > APP_CAP_MAX)
		cap = APP_CAP_MAX;
	for (;;) {
		unsigned char *buf = calloc(cap, 1);
		if (!buf)
			return -1;
		if (sig_op(op, buf, cap, &used) == 0) {
			*out = buf;
			*n_rec = used / rec_sz;
			return 0;
		}
		free(buf);
		if (cap >= APP_CAP_MAX)
			return -1;
		cap *= 2;
	}
}

static void xml_escape(FILE *f, const char *s)
{
	for (; *s; s++) {
		switch (*s) {
		case '&':  fputs("&amp;", f);  break;
		case '<':  fputs("&lt;", f);   break;
		case '>':  fputs("&gt;", f);   break;
		case '"':  fputs("&quot;", f); break;
		case '\'': fputs("&apos;", f); break;
		default:   fputc(*s, f);
		}
	}
}

static int xml_emit(const char *dir, uint32_t major, uint32_t minor,
		    char cats[CAT_SLOTS][CAT_SLOT_SZ],
		    const unsigned char *apps, uint32_t n_apps)
{
	char path[4096];
	FILE *f;
	uint32_t i;

	snprintf(path, sizeof(path), "%s/cats.xml", dir);
	f = fopen(path, "w");
	if (!f) {
		fprintf(stderr, "open %s: %s\n", path, strerror(errno));
		return -1;
	}
	fprintf(f, "<?xml version=\"1.0\"?>\n<data>\n");
	fprintf(f, "\t<version major=\"%u\" minor=\"%u\" />\n", major, minor);
	fprintf(f, "\t<app_categories>\n");
	for (i = 0; i < CAT_SLOTS; i++) {
		if (!cats[i][0])
			continue;
		fprintf(f, "\t\t<app_category id=\"%u\" name=\"", 128u + i);
		xml_escape(f, cats[i]);
		fprintf(f, "\" />\n");
	}
	fprintf(f, "\t</app_categories>\n</data>\n");
	if (fclose(f) != 0) {
		fprintf(stderr, "write %s: %s\n", path, strerror(errno));
		return -1;
	}

	snprintf(path, sizeof(path), "%s/rule.xml", dir);
	f = fopen(path, "w");
	if (!f) {
		fprintf(stderr, "open %s: %s\n", path, strerror(errno));
		return -1;
	}
	fprintf(f, "<?xml version=\"1.0\"?>\n<data>\n");
	fprintf(f, "\t<version major=\"%u\" minor=\"%u\" />\n", major, minor);
	fprintf(f, "\t<ips_categories>\n");
	fprintf(f, "\t\t<ips_category id=\"16\" name=\"Access Control\" />\n");
	fprintf(f, "\t</ips_categories>\n");
	fprintf(f, "\t<app_categories>\n");
	for (i = 0; i < CAT_SLOTS; i++) {
		if (!cats[i][0])
			continue;
		fprintf(f, "\t\t<app_category id=\"%u\" name=\"", 128u + i);
		xml_escape(f, cats[i]);
		fprintf(f, "\" />\n");
	}
	fprintf(f, "\t</app_categories>\n");
	fprintf(f, "\t<applications>\n");
	for (i = 0; i < n_apps; i++) {
		const unsigned char *rec = apps + i * APP_REC_SZ;
		char name[APP_NAME_SZ + 1];
		uint32_t page = rec[0];
		uint32_t idx = rec[1] | ((uint32_t)rec[2] << 8);

		memcpy(name, rec + 3, APP_NAME_SZ);
		name[APP_NAME_SZ] = '\0';
		if (!name[0])
			continue;
		fprintf(f, "\t\t<application cat_id=\"%u\" app_id=\"%u\" name=\"",
			128u + page, idx);
		xml_escape(f, name);
		fprintf(f, "\" />\n");
	}
	fprintf(f, "\t</applications>\n</data>\n");
	if (fclose(f) != 0) {
		fprintf(stderr, "write %s: %s\n", path, strerror(errno));
		return -1;
	}
	return 0;
}

static int cmd_check(void)
{
	uint32_t major, minor, patch;

	if (get_sig_ver(&major, &minor, &patch) != 0)
		return 1;
	printf("Signature version: major = %u, minor = %u, patch = %u\n",
	       major, minor, patch);
	if (major == 0 && minor == 0)
		printf("(version 0.0 -- no signature loaded?)\n");
	return 0;
}

static int cmd_dump(void)
{
	char cats[CAT_SLOTS][CAT_SLOT_SZ];
	unsigned char *apps = NULL;
	uint32_t major, minor, patch, nr_cats = 0, nr_apps = 0, nr_combos = 0;
	uint32_t n_apps = 0, i, named = 0;
	int rc = 0;

	if (get_sig_ver(&major, &minor, &patch) != 0)
		return 1;
	printf("signature version: %u.%u.%u\n", major, minor, patch);
	if (get_nr_u16(TDTS_SHELL_IOCTL_SIG_OP_GET_NR_CAT_NAME, &nr_cats) != 0 ||
	    get_cat_names(cats) != 0 ||
	    get_nr_u16(TDTS_SHELL_IOCTL_SIG_OP_GET_NR_APP_NAME, &nr_apps) != 0 ||
	    get_nr_u32(TDTS_SHELL_IOCTL_SIG_OP_GET_NR_APP_ID, &nr_combos) != 0)
		return 1;
	for (i = 0; i < CAT_SLOTS; i++)
		if (cats[i][0])
			named++;
	printf("categories: %u slots, %u named\n", nr_cats, named);
	for (i = 0; i < CAT_SLOTS; i++)
		if (cats[i][0])
			printf("cat %u %s\n", i, cats[i]);
	if (get_records(TDTS_SHELL_IOCTL_SIG_OP_GET_APP_NAME, APP_REC_SZ,
			&apps, &n_apps, nr_apps) != 0)
		return 1;
	if (n_apps != nr_apps)
		printf("note: %u app records vs %u reported\n", n_apps, nr_apps);
	for (i = 0; i < n_apps; i++) {
		const unsigned char *rec = apps + i * APP_REC_SZ;
		char name[APP_NAME_SZ + 1];

		memcpy(name, rec + 3, APP_NAME_SZ);
		name[APP_NAME_SZ] = '\0';
		printf("app %u %u %s\n", rec[0], rec[1] | ((uint32_t)rec[2] << 8), name);
	}
	printf("appid combinations: %u\n", nr_combos);
	free(apps);
	return rc;
}

static int cmd_xml(const char *dir)
{
	char cats[CAT_SLOTS][CAT_SLOT_SZ];
	unsigned char *apps = NULL;
	uint32_t major, minor, patch, nr_apps = 0, n_apps = 0;
	int rc;

	if (get_sig_ver(&major, &minor, &patch) != 0)
		return 1;
	if (get_cat_names(cats) != 0)
		return 1;
	if (get_nr_u16(TDTS_SHELL_IOCTL_SIG_OP_GET_NR_APP_NAME, &nr_apps) != 0)
		return 1;
	if (get_records(TDTS_SHELL_IOCTL_SIG_OP_GET_APP_NAME, APP_REC_SZ,
			&apps, &n_apps, nr_apps) != 0)
		return 1;
	if (n_apps == 0) {
		fprintf(stderr, "no application records -- regenerating nothing\n");
		free(apps);
		return 2;
	}
	rc = xml_emit(dir, major, minor, cats, apps, n_apps);
	free(apps);
	return rc;
}

static int cmd_raw(int op, uint32_t len)
{
	unsigned char *buf;
	uint32_t used = 0, i;
	int rc;

	if (len == 0 || len > APP_CAP_MAX) {
		fprintf(stderr, "bad length %u\n", len);
		return 2;
	}
	buf = calloc(len, 1);
	if (!buf)
		return 1;
	rc = sig_op(op, buf, len, &used);
	if (rc == 0) {
		printf("op=%d used=%u\n", op, used);
		for (i = 0; i < used; i++)
			printf("%02x%c", buf[i], (i % 16 == 15) ? '\n' : ' ');
		if (used % 16)
			printf("\n");
	}
	free(buf);
	return rc == 0 ? 0 : 1;
}

static void usage(void)
{
	fprintf(stderr,
		"Usage: tdts-dpi-dump [check|dump|xml <DIR>|raw <op> <len>]\n"
		"  check        print version of the loaded signature\n"
		"  dump         dump category/application tables (text)\n"
		"  xml <DIR>    write DIR/rule.xml and DIR/cats.xml\n"
		"  raw <op> <len>  hex dump of an op's output (debug)\n");
}

int main(int argc, char **argv)
{
	if (argc == 2 && !strcmp(argv[1], "check"))
		return cmd_check();
	if (argc == 2 && !strcmp(argv[1], "dump"))
		return cmd_dump();
	if (argc == 3 && !strcmp(argv[1], "xml"))
		return cmd_xml(argv[2]);
	if (argc == 4 && !strcmp(argv[1], "raw"))
		return cmd_raw(atoi(argv[2]), (uint32_t)strtoul(argv[3], NULL, 0));
	usage();
	return 2;
}
