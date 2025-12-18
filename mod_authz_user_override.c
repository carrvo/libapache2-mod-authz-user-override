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
    const char *err = NULL;
    const ap_expr_info_t *expr = parsed_require_args;
    const char *require;

    const char *parsed_tmp, *require_word, *last_word;
    char *user_tmp;
    apr_size_t word_len;

    if (!r->user) {
        return AUTHZ_DENIED_NO_USER;
    }

    require = ap_expr_str_exec(r, expr, &err);
    if (err) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "authz_user_override authorize: require user-starts-with: Can't "
                      "evaluate require expression: %s", err);
        return AUTHZ_DENIED;
    }

    parsed_tmp = require;
    while ((require_word = ap_getword_conf(r->pool, &parsed_tmp)) && require_word[0]) {
        // truncate the user because it could be a sub-path of the provided value
        word_len = strlen(require_word);
        user_tmp = apr_pcalloc(r->pool, word_len*sizeof(char));
        (void)apr_cpystrn(user_tmp, r->user, word_len);
        if (!strcmp(user_tmp, require_word)) {
            return AUTHZ_GRANTED;
        }
        last_word = require_word;
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "access to %s failed, reason: user '%s' does not meet "
                  "'require'ments for user to be allowed access "
                  "(last checked '%s')",
                  r->uri, r->user, last_word);

    return AUTHZ_DENIED;
}

static const char *user_parse_config(cmd_parms *cmd, const char *require_line,
                                     const void **parsed_require_line)
{
    const char *expr_err = NULL;
    ap_expr_info_t *expr;

    expr = ap_expr_parse_cmd(cmd, require_line, AP_EXPR_FLAG_STRING_RESULT,
            &expr_err, NULL);

    if (expr_err)
        return apr_pstrcat(cmd->temp_pool,
                           "Cannot parse expression in require line: ",
                           expr_err, NULL);

    *parsed_require_line = expr;

    return NULL;
}

static const authz_provider authz_user_override_provider =
{
    &user_check_authorization,
    &user_parse_config,
};

static void register_hooks(apr_pool_t *p)
{
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "user-starts-with",
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
