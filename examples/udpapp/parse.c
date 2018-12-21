/*
 * Copyright (c) 2016-2017  Intel Corporation.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "netbe.h"
#include "parse.h"

#define DEF_LINE_NUM	0x400

#define	OPT_SHORT_SBULK		'B'
#define	OPT_LONG_SBULK		"sburst"

#define	OPT_SHORT_CTXFLAGS	'C'
#define	OPT_LONG_CTXFLAGS	"ctxflags"

#define	OPT_SHORT_PROMISC	'P'
#define	OPT_LONG_PROMISC	"promisc"

#define	OPT_SHORT_RBUFS	'R'
#define	OPT_LONG_RBUFS	"rbufs"

#define	OPT_SHORT_SBUFS	'S'
#define	OPT_LONG_SBUFS	"sbufs"

#define	OPT_SHORT_BECFG	'b'
#define	OPT_LONG_BECFG	"becfg"

#define	OPT_SHORT_TXCNT	'c'
#define	OPT_LONG_TXCNT	"txcnt"

#define	OPT_SHORT_STREAMS	's'
#define	OPT_LONG_STREAMS	"streams"

#define OPT_SHORT_HASH         'H'
#define OPT_LONG_HASH          "hash"

#define OPT_SHORT_SEC_KEY         'K'
#define OPT_LONG_SEC_KEY          "seckey"

#define	OPT_SHORT_VERBOSE	'v'
#define	OPT_LONG_VERBOSE	"verbose"

#define	OPT_SHORT_WINDOW	'w'
#define	OPT_LONG_WINDOW		"initial-window"

#define	OPT_SHORT_TIMEWAIT	'W'
#define	OPT_LONG_TIMEWAIT	"timewait"

#define	OPT_SHORT_LOCAL_ADDR	'a'
#define	OPT_LONG_LOCAL_ADDR	"laddr"

#define	OPT_SHORT_LOCAL_PORT	'p'
#define	OPT_LONG_LOCAL_PORT	"lport"

static const struct option long_opt[] = {
	{OPT_LONG_SBULK, 1, 0, OPT_SHORT_SBULK},
	{OPT_LONG_CTXFLAGS, 1, 0, OPT_SHORT_CTXFLAGS},
	{OPT_LONG_RBUFS, 1, 0, OPT_SHORT_RBUFS},
	{OPT_LONG_SBUFS, 1, 0, OPT_SHORT_SBUFS},
	{OPT_LONG_BECFG, 1, 0, OPT_SHORT_BECFG},
	{OPT_LONG_STREAMS, 1, 0, OPT_SHORT_STREAMS},
	{OPT_LONG_HASH, 1, 0, OPT_SHORT_HASH},
	{OPT_LONG_SEC_KEY, 1, 0, OPT_SHORT_SEC_KEY},
	{OPT_LONG_VERBOSE, 1, 0, OPT_SHORT_VERBOSE},
	{OPT_LONG_WINDOW, 1, 0, OPT_SHORT_WINDOW},
	{OPT_LONG_TIMEWAIT, 1, 0, OPT_SHORT_TIMEWAIT},
	{OPT_LONG_TXCNT, 1, 0, OPT_SHORT_TXCNT},
	{OPT_LONG_LOCAL_ADDR, 1, 0, OPT_SHORT_LOCAL_ADDR},
	{OPT_LONG_LOCAL_PORT, 1, 0, OPT_SHORT_LOCAL_PORT},
	{NULL, 0, 0, 0}
};

static int
parse_uint_val(__rte_unused const char *key, const char *val, void *prm)
{
	union parse_val *rv;
	unsigned long v;
	char *end;

	rv = prm;
	errno = 0;
	v = strtoul(val, &end, 0);
	if (errno != 0 || end[0] != 0 || v > UINT32_MAX)
		return -EINVAL;

	rv->u64 = v;
	return 0;
}

static int
parse_ipv4_val(__rte_unused const char *key, const char *val, void *prm)
{
	union parse_val *rv;

	rv = prm;
	if (inet_pton(AF_INET, val, &rv->in.addr4) != 1)
		return -EINVAL;
	rv->in.family = AF_INET;
	return 0;
}

static int
parse_ipv6_val(__rte_unused const char *key, const char *val, void *prm)
{
	union parse_val *rv;

	rv = prm;
	if (inet_pton(AF_INET6, val, &rv->in.addr6) != 1)
		return -EINVAL;
	rv->in.family = AF_INET6;
	return 0;
}

static int
parse_ip_val(__rte_unused const char *key, const char *val, void *prm)
{
	if (parse_ipv6_val(key, val, prm) != 0 &&
			parse_ipv4_val(key, val, prm) != 0)
		return -EINVAL;
	return 0;
}

#define PARSE_UINT8x16(s, v, l)	                          \
do {                                                      \
	char *end;                                        \
	unsigned long t;                                  \
	errno = 0;                                        \
	t = strtoul((s), &end, 16);                       \
	if (errno != 0 || end[0] != (l) || t > UINT8_MAX) \
		return -EINVAL;                           \
	(s) = end + 1;                                    \
	(v) = t;                                          \
} while (0)

static int
parse_mac_val(__rte_unused const char *key, const char *val, void *prm)
{
	union parse_val *rv;
	const char *s;

	rv = prm;
	s = val;

	PARSE_UINT8x16(s, rv->mac.addr_bytes[0], ':');
	PARSE_UINT8x16(s, rv->mac.addr_bytes[1], ':');
	PARSE_UINT8x16(s, rv->mac.addr_bytes[2], ':');
	PARSE_UINT8x16(s, rv->mac.addr_bytes[3], ':');
	PARSE_UINT8x16(s, rv->mac.addr_bytes[4], ':');
	PARSE_UINT8x16(s, rv->mac.addr_bytes[5], 0);
	return 0;
}

static int
parse_lcore_list_val(__rte_unused const char *key, const char *val, void *prm)
{
	union parse_val *rv;
	unsigned long a, b;
	uint32_t i;
	char *end;

	rv = prm;

	errno = 0;
	a = strtoul(val, &end, 0);
	if (errno != 0 || (end[0] != 0 && end[0] != '-') || a > UINT32_MAX)
		return -EINVAL;

	if (end[0] == '-') {
		val = end + 1;
		errno = 0;
		b = strtoul(val, &end, 0);
		if (errno != 0 || end[0] != 0 || b > UINT32_MAX)
			return -EINVAL;
	} else
		b = a;

	if (a <= b) {
		for (i = a; i <= b; i++)
			CPU_SET(i, &rv->cpuset);
	} else {
		RTE_LOG(ERR, USER1,
			"%s: lcores not in ascending order\n", __func__);
		return -EINVAL;
	}

	return 0;
}

static int
parse_kvargs(const char *arg, const char *keys_man[], uint32_t nb_man,
	const char *keys_opt[], uint32_t nb_opt,
	const arg_handler_t hndl[], union parse_val val[])
{
	uint32_t j, k;

	struct rte_kvargs *kvl;

	kvl = rte_kvargs_parse(arg, NULL);
	if (kvl == NULL) {
		RTE_LOG(ERR, USER1,
			"%s: invalid parameter: %s\n",
			__func__, arg);
		return -EINVAL;
	}

	for (j = 0; j != nb_man; j++) {
		if (rte_kvargs_count(kvl, keys_man[j]) == 0) {
			RTE_LOG(ERR, USER1,
				"%s: %s missing mandatory key: %s\n",
				__func__, arg, keys_man[j]);
			rte_kvargs_free(kvl);
			return -EINVAL;
		}
	}

	for (j = 0; j != nb_man; j++) {
		if (rte_kvargs_process(kvl, keys_man[j], hndl[j],
				val + j) != 0) {
			RTE_LOG(ERR, USER1,
				"%s: %s invalid value for man key: %s\n",
				__func__, arg, keys_man[j]);
			rte_kvargs_free(kvl);
			return -EINVAL;
		}
	}

	for (j = 0; j != nb_opt; j++) {
		k = j + nb_man;
		if (rte_kvargs_process(kvl, keys_opt[j], hndl[k],
				val + k) != 0) {
			RTE_LOG(ERR, USER1,
				"%s: %s invalid value for opt key: %s\n",
				__func__, arg, keys_opt[j]);
			rte_kvargs_free(kvl);
			return -EINVAL;
		}
	}

	rte_kvargs_free(kvl);
	return 0;
}

int
parse_netbe_arg(struct netbe_port *prt, const char *arg, rte_cpuset_t *pcpu)
{
	int32_t rc;
	uint32_t i, j, nc;

	static const char *keys_man[] = {
		"port",
		"lcore",
	};

	static const char *keys_opt[] = {
		"mtu",
		"rx_offload",
		"tx_offload",
		"ipv4",
		"ipv6",
	};

	static const arg_handler_t hndl[] = {
		parse_uint_val,
		parse_lcore_list_val,
		parse_uint_val,
		parse_uint_val,
		parse_uint_val,
		parse_ipv4_val,
		parse_ipv6_val,
	};

	union parse_val val[RTE_DIM(hndl)];

	memset(val, 0, sizeof(val));
	val[2].u64 = ETHER_MAX_LEN - ETHER_CRC_LEN;

	rc = parse_kvargs(arg, keys_man, RTE_DIM(keys_man),
		keys_opt, RTE_DIM(keys_opt), hndl, val);
	if (rc != 0)
		return rc;

	prt->id = val[0].u64;

	for (i = 0, nc = 0; i < RTE_MAX_LCORE; i++)
		nc += CPU_ISSET(i, &val[1].cpuset);
	prt->lcore_id = rte_zmalloc(NULL, nc * sizeof(prt->lcore_id[0]),
		RTE_CACHE_LINE_SIZE);
	prt->nb_lcore = nc;

	for (i = 0, j = 0; i < RTE_MAX_LCORE; i++)
		if (CPU_ISSET(i, &val[1].cpuset))
			prt->lcore_id[j++] = i;
	CPU_OR(pcpu, pcpu, &val[1].cpuset);

	prt->mtu = val[2].u64;
	prt->rx_offload = val[3].u64;
	prt->tx_offload = val[4].u64;
	prt->ipv4 = val[5].in.addr4.s_addr;
	prt->ipv6 = val[6].in.addr6;

	return 0;
}

static int
check_netbe_dest(const struct netbe_dest *dst)
{
	if (dst->port >= RTE_MAX_ETHPORTS) {
		RTE_LOG(ERR, USER1, "%s(line=%u) invalid port=%u",
			__func__, dst->line, dst->port);
		return -EINVAL;
	} else if ((dst->family == AF_INET &&
			dst->prfx > sizeof(struct in_addr) * CHAR_BIT) ||
			(dst->family == AF_INET6 &&
			dst->prfx > sizeof(struct in6_addr) * CHAR_BIT)) {
		RTE_LOG(ERR, USER1, "%s(line=%u) invalid masklen=%u",
			__func__, dst->line, dst->prfx);
		return -EINVAL;
	} else if (dst->mtu > ETHER_MAX_JUMBO_FRAME_LEN - ETHER_CRC_LEN) {
		RTE_LOG(ERR, USER1, "%s(line=%u) invalid mtu=%u",
			__func__, dst->line, dst->mtu);
		return -EINVAL;
	}
	return 0;
}

static int
parse_netbe_dest(struct netbe_dest *dst, const char *arg)
{
	int32_t rc;

	static const char *keys_man[] = {
		"port",
		"addr",
		"masklen",
		"mac",
	};

	static const char *keys_opt[] = {
		"mtu",
	};

	static const arg_handler_t hndl[] = {
		parse_uint_val,
		parse_ip_val,
		parse_uint_val,
		parse_mac_val,
		parse_uint_val,
	};

	union parse_val val[RTE_DIM(hndl)];

	/* set default values. */
	memset(val, 0, sizeof(val));
	val[4].u64 = ETHER_MAX_JUMBO_FRAME_LEN - ETHER_CRC_LEN;

	rc = parse_kvargs(arg, keys_man, RTE_DIM(keys_man),
		keys_opt, RTE_DIM(keys_opt), hndl, val);
	if (rc != 0)
		return rc;

	dst->port = val[0].u64;
	dst->family = val[1].in.family;
	if (val[1].in.family == AF_INET)
		dst->ipv4 = val[1].in.addr4;
	else
		dst->ipv6 = val[1].in.addr6;
	dst->prfx = val[2].u64;
	memcpy(&dst->mac, &val[3].mac, sizeof(dst->mac));
	dst->mtu = val[4].u64;

	return 0;
}

int
netbe_parse_dest(const char *fname, struct netbe_dest_prm *prm)
{
	uint32_t i, ln, n, num;
	int32_t rc;
	size_t sz;
	char *s;
	FILE *f;
	struct netbe_dest *dp;
	char line[LINE_MAX];

	f = fopen(fname, "r");
	if (f == NULL) {
		RTE_LOG(ERR, USER1, "%s failed to open file \"%s\"\n",
			__func__, fname);
		return -EINVAL;
	}

	n = 0;
	num = 0;
	dp = NULL;
	rc = 0;
	for (ln = 0; fgets(line, sizeof(line), f) != NULL; ln++) {

		/* skip spaces at the start. */
		for (s = line; isspace(s[0]); s++)
			;

		/* skip comment line. */
		if (s[0] == '#' || s[0] == 0)
			continue;

		/* skip spaces at the end. */
		for (i = strlen(s); i-- != 0 && isspace(s[i]); s[i] = 0)
			;

		if (n == num) {
			num += DEF_LINE_NUM;
			sz = sizeof(dp[0]) * num;
			dp = realloc(dp, sizeof(dp[0]) * num);
			if (dp == NULL) {
				RTE_LOG(ERR, USER1,
					"%s(%s) allocation of %zu bytes "
					"failed\n",
					__func__, fname, sz);
				rc = -ENOMEM;
				break;
			}
			memset(&dp[n], 0, sizeof(dp[0]) * (num - n));
		}

		dp[n].line = ln + 1;
		rc = parse_netbe_dest(dp + n, s);
		rc = (rc != 0) ? rc : check_netbe_dest(dp + n);
		if (rc != 0) {
			RTE_LOG(ERR, USER1, "%s(%s) failed to parse line %u\n",
				__func__, fname, dp[n].line);
			break;
		}
		n++;
	}

	fclose(f);

	if (rc != 0) {
		free(dp);
		dp = NULL;
		n = 0;
	}

	prm->dest = dp;
	prm->nb_dest = n;
	return rc;
}

static uint32_t
parse_hash_alg(const char *val)
{
	if (strcmp(val, "jhash") == 0)
		return TLE_JHASH;
	else if (strcmp(val, "siphash") == 0)
		return TLE_SIPHASH;
	else
		return TLE_HASH_NUM;
}

static int
read_tx_content(const char *fname, struct tx_content *tx)
{
	int32_t fd, rc;
	ssize_t sz;
	struct stat st;

	rc = stat(fname, &st);
	if (rc != 0)
		return -errno;

	tx->data = rte_malloc(NULL, st.st_size, RTE_CACHE_LINE_SIZE);
	if (tx->data == NULL) {
		RTE_LOG(ERR, USER1, "%s(%s): failed to alloc %zu bytes;\n",
			__func__, fname, st.st_size);
		return -ENOMEM;
	}

	fd = open(fname, O_RDONLY);
	sz = read(fd, tx->data, st.st_size);

	RTE_LOG(NOTICE, USER1, "%s(%s): read %zd bytes from fd=%d;\n",
		__func__, fname, sz, fd);

	close(fd);

	if (sz != st.st_size) {
		rc = -errno;
		sz = 0;
		rte_free(tx->data);
	}

	tx->sz = sz;
	return rc;
}


int
parse_app_options(int argc, char **argv, struct netbe_cfg *cfg, struct tle_ctx_param *ctx_prm, char *becfg_fname, struct netfe_lcore_prm *feprm)
{
	int32_t opt, opt_idx, rc;
	uint64_t v;
	uint32_t i, j, n, nc;
	rte_cpuset_t cpuset;

	optind = 0;
	optarg = NULL;
	
	// set default
	feprm->max_streams = 1;
	feprm->nb_streams = 1;
	feprm->stream = malloc(sizeof(struct netfe_stream_prm));

	while ((opt = getopt_long(argc, argv, "b:B:C:c:LPR:S:s:v:H:K:W:w:a:p:",
			long_opt, &opt_idx)) != EOF) {
		if (opt == OPT_SHORT_SBULK) {
			rc = parse_uint_val(NULL, optarg, &v);
			if (rc < 0)
				rte_exit(EXIT_FAILURE, "%s: invalid value: %s "
					"for option: \'%c\'\n",
					__func__, optarg, opt);
			ctx_prm->send_bulk_size = v;
		} else if (opt == OPT_SHORT_CTXFLAGS) {
			rc = parse_uint_val(NULL, optarg, &v);
			if (rc < 0)
				rte_exit(EXIT_FAILURE, "%s: invalid value: %s "
					"for option: \'%c\'\n",
					__func__, optarg, opt);
			ctx_prm->flags = v;
		} else if (opt == OPT_SHORT_PROMISC) {
			cfg->promisc = 1;
		} else if (opt == OPT_SHORT_RBUFS) {
			rc = parse_uint_val(NULL, optarg, &v);
			if (rc < 0)
				rte_exit(EXIT_FAILURE, "%s: invalid value: %s "
					"for option: \'%c\'\n",
					__func__, optarg, opt);
			ctx_prm->max_stream_rbufs = v;
		} else if (opt == OPT_SHORT_SBUFS) {
			rc = parse_uint_val(NULL, optarg, &v);
			if (rc < 0)
				rte_exit(EXIT_FAILURE, "%s: invalid value: %s "
					"for option: \'%c\'\n",
					__func__, optarg, opt);
			ctx_prm->max_stream_sbufs = v;
		} else if (opt == OPT_SHORT_STREAMS) {
			rc = parse_uint_val(NULL, optarg, &v);
			if (rc < 0)
				rte_exit(EXIT_FAILURE, "%s: invalid value: %s "
					"for option: \'%c\'\n",
					__func__, optarg, opt);
			ctx_prm->max_streams = v;
		} else if (opt == OPT_SHORT_VERBOSE) {
			rc = parse_uint_val(NULL, optarg, &v);
			if (rc < 0)
				rte_exit(EXIT_FAILURE, "%s: invalid value: %s "
					"for option: \'%c\'\n",
					__func__, optarg, opt);
			verbose = (v > VERBOSE_NUM) ? VERBOSE_NUM : v;
		} else if (opt == OPT_SHORT_BECFG) {
			snprintf(becfg_fname, PATH_MAX, "%s",
				optarg);
		} else if (opt == OPT_SHORT_HASH) {
			ctx_prm->hash_alg = parse_hash_alg(optarg);
			if (ctx_prm->hash_alg >= TLE_HASH_NUM) {
				rte_exit(EXIT_FAILURE,
					"%s: invalid hash algorithm %s "
					"for option: \'%c\'\n",
					__func__, optarg, opt);
			}
		} else if (opt == OPT_SHORT_SEC_KEY) {
			n = strlen(optarg);
			if (n != sizeof(ctx_prm->secret_key)) {
				rte_exit(EXIT_FAILURE,
					"%s: invalid length %s "
					"for option \'%c\' "
					"must be 16 characters long\n",
					__func__, optarg, opt);
			}
			memcpy(&ctx_prm->secret_key, optarg,
				sizeof(ctx_prm->secret_key));
		} else if (opt == OPT_SHORT_WINDOW) {
			rc = parse_uint_val(NULL, optarg, &v);
			if (rc < 0)
				rte_exit(EXIT_FAILURE, "%s: invalid value: %s "
					"for option: \'%c\'\n",
					__func__, optarg, opt);
			ctx_prm->icw = v;
		} else if (opt == OPT_SHORT_TIMEWAIT) {
			rc = parse_uint_val(NULL, optarg, &v);
			if (rc < 0)
				rte_exit(EXIT_FAILURE, "%s: invalid value: %s "
					"for option: \'%c\'\n",
					__func__, optarg, opt);
			ctx_prm->timewait = v;
		} else if (opt == OPT_SHORT_TXCNT) {
			rc = read_tx_content(optarg, &tx_content);
			if (rc < 0)
				rte_exit(EXIT_FAILURE,
					"%s: failed to read tx contents "
					"from \'%s\', error code: %d(%s)\n",
					__func__, optarg, rc, strerror(-rc));
		} else if (opt == OPT_SHORT_LOCAL_ADDR) {
			feprm->stream->sprm.local_addr.ss_family = AF_INET;;
			struct sockaddr_in *si = (struct sockaddr_in *)&feprm->stream->sprm.local_addr;
			rc = inet_pton(AF_INET, optarg, &si->sin_addr) ;
			if (rc != 1)
				rte_exit(EXIT_FAILURE,
					"%s: failed to parse local address %s, error code: %d(%s)\n",
					__func__, optarg, rc, strerror(-rc));
		       	
		} else if (opt == OPT_SHORT_LOCAL_PORT) {
			struct sockaddr_in *si = (struct sockaddr_in *)&feprm->stream->sprm.local_addr;
			int port;
		       	rc =	parse_uint_val(NULL, optarg, &port);
			if (rc != 0)
				rte_exit(EXIT_FAILURE,
					"%s: failed to parse local port %s, error code: %d(%s)\n",
					__func__, optarg, rc, strerror(-rc));
			si->sin_port = rte_cpu_to_be_16((uint16_t)port);
		} else {
			rte_exit(EXIT_FAILURE,
				"%s: unknown option: \'%c\'\n",
				__func__, opt);
		}
	}

	/* parse port params */
	argc -= optind;
	argv += optind;

	/* allocate memory for number of ports defined */
	n = (uint32_t)argc;
	cfg->prt = rte_zmalloc(NULL, sizeof(struct netbe_port) * n,
		RTE_CACHE_LINE_SIZE);
	cfg->prt_num = n;

	rc = 0;
	for (i = 0; i != n; i++) {
		rc = parse_netbe_arg(cfg->prt + i, argv[i], &cpuset);
		if (rc != 0) {
			RTE_LOG(ERR, USER1,
				"%s: processing of \"%s\" failed with error "
				"code: %d\n", __func__, argv[i], rc);
			for (j = 0; j != i; j++)
				rte_free(cfg->prt[j].lcore_id);
			rte_free(cfg->prt);
			return rc;
		}
	}

	/* count the number of CPU defined in ports */
	for (i = 0, nc = 0; i < RTE_MAX_LCORE; i++)
		nc += CPU_ISSET(i, &cpuset);

	/* allocate memory for number of CPU defined */
	cfg->cpu = rte_zmalloc(NULL, sizeof(struct netbe_lcore) * nc,
		RTE_CACHE_LINE_SIZE);

	// configure lp
       	feprm->stream->lcore = cfg->prt[0].lcore_id[0];
	feprm->stream->sprm.remote_addr.ss_family = AF_INET;;
	struct sockaddr_in *si = (struct sockaddr_in *)&feprm->stream->sprm.remote_addr;
	si->sin_port = rte_cpu_to_be_16(0);
	rc = inet_pton(AF_INET, "0.0.0.0", &si->sin_addr) ;
	if (rc != 1)
		rte_exit(EXIT_FAILURE,
			"%s: failed to parse local address %s, error code: %d(%s)\n",
			__func__, optarg, rc, strerror(-rc));
	return 0;
}
