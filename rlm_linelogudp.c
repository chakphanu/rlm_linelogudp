/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id: ed94bba8f0fe287fedd6ee28e218a89af2ee6dc8 $
 * @file rlm_linelogudp.c
 * @brief linelogudp module code.
 *
 * @copyright 2013 The FreeRADIUS server project
 * @copyright 2013 your name \<your address\>
 */
RCSID("$Id: ed94bba8f0fe287fedd6ee28e218a89af2ee6dc8 $")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>

#include <sys/socket.h>

#ifndef WITH_ACCOUNTING
#define WITH_ACCOUNTING
#endif

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct rlm_linelogudp_t {
	CONF_SECTION	*cs;

	bool		boolean;
	uint32_t	value;
	char const	*string;
	fr_ipaddr_t	ipaddr;
	int			sockfd;
	fr_ipaddr_t		dst_ipaddr;
	uint16_t		port;
	char const	*reference;
	char const	*line;



} rlm_linelogudp_t;

/*
 *	A mapping of configuration file names to internal variables.
 */
static const CONF_PARSER module_config[] = {
	{ "dst_ipaddr", FR_CONF_OFFSET(PW_TYPE_IPV4_ADDR, rlm_linelogudp_t, dst_ipaddr), "127.0.0.1" },
	{ "port", FR_CONF_OFFSET(PW_TYPE_SHORT, rlm_linelogudp_t, port), "8089" },
	{ "reference", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_linelogudp_t, reference), NULL },
	{ "format", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_linelogudp_t, line), NULL },

	CONF_PARSER_TERMINATOR
};

static int rlm_linelogudp_cmp(UNUSED void *instance, REQUEST *request, UNUSED VALUE_PAIR *thing, VALUE_PAIR *check,
			   UNUSED VALUE_PAIR *check_pairs, UNUSED VALUE_PAIR **reply_pairs)
{
	rad_assert(check->da->type == PW_TYPE_STRING);

	RINFO("linelogudp-Paircmp called with \"%s\"", check->vp_strvalue);

	if (strcmp(check->vp_strvalue, "yes") == 0) return 0;
	return 1;
}

/*
 *	Do any per-module initialization that is separate to each
 *	configured instance of the module.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 */
static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	rlm_linelogudp_t *inst = instance;
	ATTR_FLAGS flags;

	memset(&flags, 0, sizeof(flags));
	/*
	 *	Do more work here
	 */


	inst->sockfd = fr_socket_client_udp(NULL, &inst->dst_ipaddr, inst->port, true);
		if (inst->sockfd < 0) {
			ERROR("Failed opening UDP socket");
			return -1;
		}

	inst->cs = conf;


	return 0;
}


/*
 *	Escape unprintable characters.
 */
static size_t linelog_escape_func(UNUSED REQUEST *request,
		char *out, size_t outlen, char const *in,
		UNUSED void *arg)
{
	if (outlen == 0) return 0;

	if (outlen == 1) {
		*out = '\0';
		return 0;
	}

	return fr_prints(out, outlen, in, -1, 0);
}


/*
 *	Find the named user in this modules database.  Create the set
 *	of attribute-value pairs to check and reply with for this user
 *	from the database. The authentication code only needs to check
 *	the password, the rest is done here.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authorize(UNUSED void *instance, REQUEST *request)
{
	VALUE_PAIR *state;

	/*
	 *  Look for the 'state' attribute.
	 */
	state = fr_pair_find_by_num(request->packet->vps, PW_STATE, 0, TAG_ANY);
	if (state != NULL) {
		RDEBUG("Found reply to access challenge");
		return RLM_MODULE_OK;
	}

	/*
	 *  Create the challenge, and add it to the reply.
	 */
	pair_make_reply("Reply-Message", "This is a challenge", T_OP_EQ);
	pair_make_reply("State", "0", T_OP_EQ);

	/*
	 *  Mark the packet as an Access-Challenge packet.
	 *
	 *  The server will take care of sending it to the user.
	 */
	request->reply->code = PW_CODE_ACCESS_CHALLENGE;
	RDEBUG("Sending Access-Challenge");

	return RLM_MODULE_HANDLED;
}

/*
 *	Authenticate the user with the given password.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authenticate(UNUSED void *instance, UNUSED REQUEST *request)
{
	return RLM_MODULE_OK;
}

#ifdef WITH_ACCOUNTING
/*
 *	Massage the request before recording it or proxying it
 */
static rlm_rcode_t CC_HINT(nonnull) mod_preacct(UNUSED void *instance, UNUSED REQUEST *request)
{
	return RLM_MODULE_OK;
}

/*
 *	Write accounting information to this modules database.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_accounting(UNUSED void *instance, UNUSED REQUEST *request)
{
	RDEBUG("mod_accounting call");
	rlm_linelogudp_t *inst = instance;
	char const *value = inst->line;

	char path[2048];
	char line[4096];

	line[0] = '\0';

	if (inst->reference) {
		CONF_ITEM *ci;
		CONF_PAIR *cp;


		if (radius_xlat(line + 1, sizeof(line) - 1, request, inst->reference, linelog_escape_func, NULL) < 0) {
			return RLM_MODULE_FAIL;
		}


		line[0] = '.';	/* force to be in current section */

		/*
		*	Don't allow it to go back up
		*/
		if (line[1] == '.') goto do_log;

		RDEBUG2("line0 \"%s\"", line);

		ci = cf_reference_item(NULL, inst->cs, line);
		if (!ci) {
			RDEBUG2("No such entry \"%s\"", line);
			return RLM_MODULE_NOOP;
		}
		RDEBUG2("line1 \"%s\"", line);

		if (!cf_item_is_pair(ci)) {
			RDEBUG2("Entry \"%s\" is not a variable assignment ", line);
			goto do_log;
		}

		cp = cf_item_to_pair(ci);
		value = cf_pair_value(cp);
		if (!value) {
			RWDEBUG2("Entry \"%s\" has no value", line);
			return RLM_MODULE_OK;
		}

		/*
			*	Value exists, but is empty.  Don't log anything.
			*/
		if (!*value) return RLM_MODULE_OK;
	}


	do_log:
		/*
	 	*	FIXME: Check length.
	 	*/
		if (radius_xlat(line, sizeof(line) - 1, request, value, linelog_escape_func, NULL) < 0) {
			return RLM_MODULE_FAIL;
		}

		strcat (line, "\n");
		write(inst->sockfd, line, strlen(line));
		return RLM_MODULE_OK;
}

/*
 *	See if a user is already logged in. Sets request->simul_count to the
 *	current session count for this user and sets request->simul_mpp to 2
 *	if it looks like a multilink attempt based on the requested IP
 *	address, otherwise leaves request->simul_mpp alone.
 *
 *	Check twice. If on the first pass the user exceeds his
 *	max. number of logins, do a second pass and validate all
 *	logins by querying the terminal server (using eg. SNMP).
 */
static rlm_rcode_t CC_HINT(nonnull) mod_checksimul(UNUSED void *instance, REQUEST *request)
{
	request->simul_count=0;

	return RLM_MODULE_OK;
}
#endif


/*
 *	Only free memory we allocated.  The strings allocated via
 *	cf_section_parse() do not need to be freed.
 */
static int mod_detach(UNUSED void *instance)
{
	/* free things here */
	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_t rlm_linelogudp;
module_t rlm_linelogudp = {
	.magic		= RLM_MODULE_INIT,
	.name		= "linelogudp",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_linelogudp_t),
	.config		= module_config,
	.instantiate	= mod_instantiate,
	.detach		= mod_detach,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate,
		[MOD_AUTHORIZE]		= mod_authorize,
#ifdef WITH_ACCOUNTING
		[MOD_PREACCT]		= mod_preacct,
		[MOD_ACCOUNTING]	= mod_accounting,
		[MOD_SESSION]		= mod_checksimul
#endif
	},
};
