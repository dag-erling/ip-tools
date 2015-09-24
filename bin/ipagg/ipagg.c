/*-
 * Copyright (c) 2015 Universitetet i Oslo
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <arpa/inet.h>
#include <netinet/in.h>

#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int verbose;
#define VERBOSE(...) do { if (verbose > 0) warnx(__VA_ARGS__); } while (0)

/*
 * How many bits to process at a time.  Lower values improve aggregation
 * but can greatly increase the memory footprint.
 */
static unsigned int bits = 4;

/*
 * Minimum prefix length, to split large ranges into smaller ones.
 */
static unsigned int minplen = 8;

/*
 * Maximum prefix length.  Ranges smaller than this will be rounded up.
 * Smaller values reduce fragmentation and memory usage.
 */
static unsigned int maxplen = 24;

/*
 * Flags
 */
static int aggregate = 1;	/* perform aggregation */
static int prefix32 = 1;	/* also print prefix for /32 */

/*
 * A node in the tree.
 */
struct node {
	uint32_t	 addr;		/* network address */
	uint8_t		 plen;		/* prefix length */
	int		 leaf:1;	/* leaf node flag */
	uint32_t	 coverage;	/* how full the subtree is */
	struct node	*sub[16];	/* children */
};

/*
 * Print the leaf nodes of a tree in order.
 */
void
print_tree(struct node *n)
{
	unsigned int i;

	if (n->leaf) {
		printf("%u.%u.%u.%u",
		    (n->addr >> 24) & 0xff,
		    (n->addr >> 16) & 0xff,
		    (n->addr >> 8) & 0xff,
		    n->addr & 0xff);
		if (prefix32 || n->plen < 32)
			printf("/%u", n->plen);
		printf("\n");
	} else {
		for (i = 0; i < (1U << bits); ++i)
			if (n->sub[i] != NULL)
				print_tree(n->sub[i]);
	}
}

/*
 * Delete all children of a given node in a tree.
 */
void
delete_children(struct node *n)
{
	unsigned int i;

	for (i = 0; i < (1U << bits); ++i) {
		if (n->sub[i] != NULL) {
			delete_children(n->sub[i]);
			free(n->sub[i]);
			n->sub[i] = NULL;
		}
	}
}

/*
 * Insert a range of addresses (specified as first and last) into a tree.
 */
void
insert_range(struct node *n, uint32_t first, uint32_t last)
{
	struct node *sn;
	uint32_t mask, fsub, lsub, mincov;
	unsigned int i;
	uint8_t splen;

	/*
	 * This is either a duplicate or a subset of a previously inserted
	 * range.
	 */
	if (n->leaf) {
		VERBOSE("%08x-%08x: subset of leaf %08x/%d",
		    first, last, n->addr, n->plen);
		return;
	}

	/*
	 * Compute the host mask for this subnet.  This is the inverse of
	 * the netmask.
	 */
	mask = 0xffffffffLU >> n->plen;

	/*
	 * Clip the range to our subnet so the caller doesn't have to (see
	 * loop below).
	 */
	if (first < n->addr)
		first = n->addr;
	if (last > (n->addr | mask))
		last = n->addr | mask;

	VERBOSE("%08x-%08x: inserting in %08x/%d",
	    first, last, n->addr, n->plen);

	/*
	 * Either the new range covers the entire subnet or we reached the
	 * maximum prefix length.
	 */
	if (n->plen >= minplen &&
	    ((first == n->addr && last == (n->addr | mask)) ||
	     n->plen + bits > maxplen)) {
		VERBOSE("%08x-%08x: covers %08x/%d",
		    first, last, n->addr, n->plen);
		delete_children(n);
		n->leaf = 1;
		n->coverage = mask + 1; /* equivalent to size of subnet */
		return;
	}

	/*
	 * Compute the prefix length for the next recursion level and find
	 * out which child node(s) we will have to descend into.
	 */
	splen = n->plen + bits;
	fsub = (first >> (32 - splen)) % (1U << bits);
	lsub = (last >> (32 - splen)) % (1U << bits);

	/*
	 * Descend into each covered child.
	 */
	for (i = fsub; i <= lsub; ++i) {
		/*
		 * Create a new node.
		 */
		if ((sn = n->sub[i]) == NULL) {
			if ((sn = calloc(1, sizeof *sn)) == NULL)
				err(1, "calloc()");
			sn->addr = n->addr | (i << (32 - splen));
			sn->plen = splen;
			VERBOSE("added node %08x/%d", sn->addr, sn->plen);
			n->sub[i] = sn;
		}
		/*
		 * Insert into subnet and adjust our coverage number.
		 */
		n->coverage -= sn->coverage;
		insert_range(sn, first, last);
		n->coverage += sn->coverage;
	}

	/*
	 * Perform aggregation, unless we are at the root.  Aggregation
	 * into the root node takes a bit more work (due to integer
	 * overflow) and is not likely to be needed.
	 *
	 * The aggregation threshold is currently 100%, i.e. we only
	 * aggregate fully covered nodes.  Depending on the data set, it
	 * may make sense to lower the threshold to as little as 25%.
	 */
	if (aggregate) {
		mincov = mask + 1; /* lower this to reduce fragmentation */
		if (n->plen >= minplen &&
		    mincov > 0 && n->coverage >= mincov) {
			VERBOSE("aggregating %08x/%d", n->addr, n->plen);
			delete_children(n);
			n->leaf = 1;
			n->coverage = mask + 1;
		}
	}
}

/*
 * Parse a line, which contains either a single address, a pair of
 * addresses separated by a hyphen, or a range in CIDR notation.
 */
int
parse_line(struct node *tree, const char *line, size_t len)
{
	char str[64];
	uint32_t first, last, mask;
	unsigned int plen;
	const char *p, *q;

	/* isolate and parse the first word */
	for (p = q = line; q < line + len && *q != '-' && *q != '/'; ++q)
		continue;
	if ((size_t)(q - p) >= sizeof str)
		goto invalid;
	memcpy(str, p, q - p);
	str[q - p] = '\0';
	/*
	 * Some inet_network() implementations will not complain about
	 * trailing garbage after a valid address.  We should have our own
	 * implementation.
	 */
	if ((first = (uint32_t)inet_network(str)) == INADDR_NONE)
		goto invalid;

	/* one of three syntaxes */
	if (q == line + len) {
		/* single address */
		last = first;
	} else if (*q == '-') {
		/* two addresses separated by a hyphen */
		for (p = ++q; q < line + len && !isspace(*q); ++q)
			continue;
		if (q != line + len)
			goto invalid;
		if ((size_t)(q - p) >= sizeof str)
			goto invalid;
		memcpy(str, p, q - p);
		str[q - p] = '\0';
		if ((last = (uint32_t)inet_network(str)) == INADDR_NONE)
			goto invalid;
	} else if (*q == '/') {
		/* subnet in CIDR notation */
		for (p = ++q; q < line + len && isdigit(*q); ++q)
			continue;
		if (q != line + len)
			goto invalid;
		if ((size_t)(q - p) > 2)
			goto invalid;
		plen = p[0] - '0';
		if (q - p == 2)
			plen = 10 * plen + (p[1] - '0');
		mask = 0xffffffffLU >> plen;
		if (first & mask)
			goto misaligned;
		last = first | mask;
	} else {
		goto invalid;
	}
	insert_range(tree, first, last);
	return (0);
invalid:
	warnx("not an address, range or subnet: %.*s", (int)len, line);
	return (-1);
misaligned:
	warnx("misaligned subnet: %.*s", (int)len, line);
	return (-1);
}

/*
 * Read lines from a file, strip trailing whitespace and pass to the
 * parser.
 */
void
read_from_file(struct node *tree, FILE *f)
{
	static char *line, *arg;
	static size_t size;
	ssize_t len;
	unsigned int i;

	while ((len = getline(&line, &size, f)) >= 0) {
		arg = line;
		while (len > 0 && isspace((unsigned char)arg[0]))
			++arg, --len;
		for (i = 0; i < len; ++i)
			if (arg[i] == '#')
				break;
		len = i;
		while (len > 0 && isspace((unsigned char)arg[len - 1]))
			--len;
		if (len > 0)
			(void)parse_line(tree, arg, len);
	}
}

/*
 * Print usage string and exit.
 */
static void
usage(void)
{

	fprintf(stderr, "usage: ipagg [-nsv] [-1|-2|-3|-4] "
	    "[-a maxplen] [-i minplen]\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct node *tree;
	int i, opt;

	while ((opt = getopt(argc, argv, "1234a:hi:nsv")) != -1)
		switch (opt) {
		case '1':
		case '2':
		case '3':
		case '4':
			bits = opt - '0';
			break;
		case 'a':
			maxplen = atoi(optarg);
			if (maxplen < 8 || maxplen > 32)
				errx(1, "invalid parameter: -%c %s", opt, optarg);
			break;
		case 'i':
			minplen = atoi(optarg);
			if (minplen < 4 || minplen > 28)
				errx(1, "invalid parameter: -%c %s", opt, optarg);
			break;
		case 'n':
			aggregate = 0;
			break;
		case 's':
			prefix32 = 0;
			break;
		case 'v':
			verbose++;
			break;
		default:
			usage();
		}

	argc -= optind;
	argv += optind;

	if (minplen > maxplen)
		errx(1, "maxplen can not be smaller than minplen");

	/* allocate empty tree */
	if ((tree = calloc(1, sizeof *tree)) == NULL)
		err(1, "calloc()");

	/*
	 * Read a list of addresses and ranges into a tree,
	 * aggregating on the fly.
	 */
	if (argc > 0) {
		/* parse arguments listed on the command line */
		for (i = 0; i < argc; ++i)
			parse_line(tree, argv[i], strlen(argv[i]));
	} else {
		/* read from standard input */
		read_from_file(tree, stdin);
	}

	/*
	 * Print the contents of the tree.
	 */
	print_tree(tree);

	exit(0);
}
