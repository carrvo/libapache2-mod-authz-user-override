/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "apr_strings.h"

#include "ap_config.h"
#include "ap_provider.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

#include <regex.h>

#include "mod_auth.h"

typedef struct {
        int dummy;  /* just here to stop compiler warnings for now. */
} authz_user_override_config_rec;

static void *create_authz_user_override_dir_config(apr_pool_t *p, char *d)
{
    authz_user_override_config_rec *conf = apr_palloc(p, sizeof(*conf));

    return conf;
}

static const command_rec authz_user_override_cmds[] =
{
    {NULL}
};

module AP_MODULE_DECLARE_DATA authz_user_override_module;

static authz_status user_check_authorization(request_rec *r,
                                             const char *require_args,
                                             const void *parsed_require_args)
{
    const char *require_word;
    const char *location_end;

    // Source - https://stackoverflow.com/a/1085120
    // Posted by Laurence Gonsalves, modified by community. See post 'Timeline' for change history
    // Retrieved 2025-12-17, License - CC BY-SA 3.0       
    regex_t *regex = apr_pcalloc(pool, sizeof(regex_t));
    regmatch_t *match = apr_pcalloc(pool, sizeof(regmatch_t));
    int reti;
    char msgbuf[100];

    /* Compile regular expression */
    reti = regcomp(regex, ".*\\(?<user>[-_\.\w\d]+\\)/?$", 0);
    if (reti) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                  "Could not compile regex");
        /* Free memory allocated to the pattern buffer by regcomp() */
        regfree(regex);
        return AUTHZ_DENIED;
    }

    /* Execute regular expression */
    reti = regexec(regex, r->uri, 1, match, 0);
    if (!reti) {
        
    }
    else if (reti == REG_NOMATCH) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                  "Regex no match found: %s", r->uri);
        /* Free memory allocated to the pattern buffer by regcomp() */
        regfree(regex);
        return AUTHZ_DENIED;
    }
    else {
        regerror(reti, regex, msgbuf, sizeof(msgbuf));
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                  "Regex match failed for %s: %s", r->uri, msgbuf);
        /* Free memory allocated to the pattern buffer by regcomp() */
        regfree(regex);
        return AUTHZ_DENIED;
    }
    /* Free memory allocated to the pattern buffer by regcomp() */
    regfree(regex);

    if (!r->user) {
        return AUTHZ_DENIED_NO_USER;
    }

    while ((require_word = ap_getword_conf(r->pool, &require_args)) && require_word[0]) {
        if (!strcmp(r->user, require_word)) {
            return AUTHZ_GRANTED;
        }
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "access to %s failed, reason: user '%s' does not meet "
                  "'require'ments for user to be allowed access",
                  r->uri, r->user);

    return AUTHZ_DENIED;
}

static const authz_provider authz_user_override_provider =
{
    &user_check_authorization,
    NULL,
};

static void register_hooks(apr_pool_t *p)
{
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "user-override",
                              AUTHZ_PROVIDER_VERSION,
                              &authz_user_override_provider, AP_AUTH_INTERNAL_PER_CONF);
}

AP_DECLARE_MODULE(authz_user_override) =
{
    STANDARD20_MODULE_STUFF,
    create_authz_user_override_dir_config, /* dir config creater */
    NULL,                         /* dir merger --- default is to override */
    NULL,                         /* server config */
    NULL,                         /* merge server config */
    authz_user_override_cmds,              /* command apr_table_t */
    register_hooks                /* register hooks */
};
