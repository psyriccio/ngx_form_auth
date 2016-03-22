#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <security/pam_appl.h>

#define NGX_PAM_SERVICE_NAME "nginx"
#define NGX_LOGIN_FIELD "login"
#define NGX_PASSWORD_FIELD "password"

#define PAM_STEP_AUTH 1
#define PAM_STEP_ACCOUNT 2
#define PAM_STEP_ALL 3

typedef struct {
    unsigned done:1;
    unsigned wait_for_more_body:1;
} ngx_http_form_auth_ctx_t;

typedef struct {
    ngx_flag_t enabled;
    ngx_str_t pam_service;
    ngx_str_t login_field;
    ngx_str_t password_field;
    ngx_flag_t set_remote_user;
} ngx_http_form_auth_loc_conf_t;

static void * ngx_http_form_auth_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_form_auth_loc_conf_t *conf;
    conf = ngx_palloc(cf->pool, sizeof(ngx_http_form_auth_loc_conf_t));
    if(conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->enabled = NGX_CONF_UNSET;
    conf->set_remote_user = NGX_CONF_UNSET;
    return conf;
}

static char * ngx_http_form_auth_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child)
{
    ngx_http_form_auth_loc_conf_t *prev = parent;
    ngx_http_form_auth_loc_conf_t *conf = child;

    ngx_conf_merge_off_value(conf->enabled, prev->enabled, 0);
    ngx_conf_merge_off_value(conf->set_remote_user, prev->set_remote_user, 0);
    ngx_conf_merge_str_value(conf->pam_service,
        prev->pam_service, NGX_PAM_SERVICE_NAME);
    ngx_conf_merge_str_value(conf->login_field, prev->login_field,
        NGX_LOGIN_FIELD);
    ngx_conf_merge_str_value(conf->password_field, prev->password_field,
        NGX_PASSWORD_FIELD);

    return NGX_CONF_OK;
}

static ngx_command_t ngx_http_form_auth_commands[] = {
    { ngx_string("form_auth"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_form_auth_loc_conf_t, enabled),
      NULL },
    { ngx_string("form_auth_pam_service"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_form_auth_loc_conf_t, pam_service),
      NULL },
    { ngx_string("form_auth_login"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_form_auth_loc_conf_t, login_field),
      NULL },
    { ngx_string("form_auth_password"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_form_auth_loc_conf_t, password_field),
      NULL },
    { ngx_string("form_auth_remote_user"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_form_auth_loc_conf_t, set_remote_user),
      NULL },

      ngx_null_command
};

static ngx_int_t ngx_http_form_auth_init(ngx_conf_t *cf);

static ngx_http_module_t ngx_http_form_auth_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_http_form_auth_init,                /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    ngx_http_form_auth_create_loc_conf,     /* create location configuration */
    ngx_http_form_auth_merge_loc_conf       /* merge location configuration */
};

ngx_module_t ngx_http_form_auth_module = {
    NGX_MODULE_V1,
    &ngx_http_form_auth_module_ctx,         /* module context */
    ngx_http_form_auth_commands,            /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit precess */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};

static void post_handler(ngx_http_request_t *r)
{
    ngx_http_form_auth_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_form_auth_module);
    ctx->done = 1;
    r->main->count--;

    if(ctx->wait_for_more_body) {
        ctx->wait_for_more_body = 0;
        ngx_http_core_run_phases(r);
    }
}

void set_str_from_buffer(ngx_http_request_t *r, ngx_str_t *str_to_set,
    ngx_str_t *field, u_char *buffer, u_char *last)
{
    u_char *pos;
    for(pos = buffer; pos < last; pos++) {
        pos = ngx_strlcasestrn(pos, last - 1, field->data, field->len - 1);
        if(pos == NULL) {
            return;
        }

        if((pos == buffer || *(pos - 1) == '&') && *(pos + field->len) == '=') {
            u_char *value = pos + field->len + 1;
            pos = ngx_strlchr(value, last, '&');
            if(pos == NULL) {
                pos = last;
            }
            str_to_set->len = pos - value;
            str_to_set->data = value;
            return;
        }
    }
}

ngx_int_t get_credentials(ngx_http_request_t *r, ngx_str_t *user_login_name,
    ngx_str_t *user_password, ngx_str_t *login_field, ngx_str_t *password_field)
{
    u_char *last, *buffer;

    if(!r->request_body || !r->request_body->bufs) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_form_auth: Empty buffers, no credentials provided");
        return NGX_DECLINED;
    }

    if(r->request_body->bufs->next) {
        size_t len = 0;
        ngx_chain_t *chain;
        for(chain = r->request_body->bufs; chain; chain = chain->next) {
            if(!chain->buf->in_file) {
                len += chain->buf->last - chain->buf->pos;
            }
        }
        if(!len) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_form_auth: Empty buffers, no credentials provided");
            return NGX_DECLINED;
        }

        buffer = ngx_palloc(r->pool, len);
        if(buffer == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_form_auth: ngx_palloc failed.");
            return NGX_ERROR;
        }
        last = buffer + len;

        for(chain = r->request_body->bufs; chain; chain = chain->next) {
            buffer = ngx_copy(buffer, chain->buf->pos,
                chain->buf->last - chain->buf->pos);
        }
    } else {
        if(!ngx_buf_size(r->request_body->bufs->buf)) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_form_auth: Empty buffer, no credentials provided");
            return NGX_DECLINED;
        }
        buffer = r->request_body->bufs->buf->pos;
        last = r->request_body->bufs->buf->last;
    }

    set_str_from_buffer(r, user_login_name, login_field, buffer, last);
    set_str_from_buffer(r, user_password, password_field, buffer, last);

    user_login_name->data[user_login_name->len] = '\0';
    user_password->data[user_password->len] = '\0';

    if(!user_login_name->len || !user_password->len) {
        return NGX_DECLINED;
    }

    return NGX_OK;
}

static int pam_conversation(int num, const struct pam_message **message,
    struct pam_response **response, void *data)
{
    if(!message || !response || !data) {
        return PAM_CONV_ERR;
    }

    struct pam_response *tmp_response =
        malloc(num * sizeof(struct pam_response));
    if(!tmp_response) {
        return PAM_CONV_ERR;
    }

    int i;
    for(i = 0; i < num; i++) {
        tmp_response[i].resp = 0;
        tmp_response[i].resp_retcode = 0;
        if(message[i]->msg_style == PAM_PROMPT_ECHO_OFF) {
            tmp_response[i].resp = strdup(data);
        } else {
            free(tmp_response);
            return PAM_CONV_ERR;
        }
    }
    *response = tmp_response;
    return PAM_SUCCESS;
}

static ngx_int_t authenticate_and_authorize(ngx_http_request_t *r,
    ngx_int_t steps, ngx_http_form_auth_loc_conf_t *loc_conf,
    const char *user, const char *password)
{
    pam_handle_t *handle = NULL;
    struct pam_conv conversation =
        { &pam_conversation, (void *)password };
    int rc = pam_start((const char *)loc_conf->pam_service.data,
        user, &conversation, &handle);

    if(rc == PAM_SUCCESS) {
        if(steps & PAM_STEP_AUTH) {
            rc = pam_authenticate(handle, PAM_DISALLOW_NULL_AUTHTOK);
            if(rc != PAM_SUCCESS) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "ngx_form_auth: Authentication failed for user %s", user);
                return NGX_HTTP_UNAUTHORIZED;
            }
            r->access_code = NGX_OK;
        }

        if((rc == PAM_SUCCESS) && (steps & PAM_STEP_ACCOUNT)) {
            rc = pam_acct_mgmt(handle, PAM_DISALLOW_NULL_AUTHTOK);
            if(rc != PAM_SUCCESS) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "ngx_form_auth: Authorization failed for user %s", user);
                return NGX_HTTP_FORBIDDEN;
            }
        }

        pam_end(handle, rc);
        if(rc == PAM_SUCCESS) {
            return NGX_OK;
        }
        return NGX_HTTP_FORBIDDEN;
    } else {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_form_auth: Unable to start PAM service: %s",
            pam_strerror(handle, rc));
        pam_end(handle, rc);
        return NGX_ERROR;
    }
}

// remote_user should only be set with Basic auth
void set_remote_user(ngx_http_request_t *r)
{
    const char *basic_pass = "ngx_form_auth_password";
    ngx_str_t user_pass, base64_user_pass, header;

    user_pass.len = r->headers_in.user.len + ngx_strlen(basic_pass) + 2;
    user_pass.data = ngx_pnalloc(r->pool, user_pass.len);
    if(user_pass.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_form_auth: Unable to set remote_user variable; not encoded.");
        return;
    }
    ngx_snprintf(user_pass.data, user_pass.len, "%s:%s",
        r->headers_in.user, basic_pass);

    base64_user_pass.len = ngx_base64_encoded_length(user_pass.len);
    base64_user_pass.data = ngx_pnalloc(r->pool, base64_user_pass.len);
    if(base64_user_pass.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_form_auth: Unable to set remote_user variable; encoded.");
        return;
    }
    ngx_encode_base64(&base64_user_pass, &user_pass);

    header.len = sizeof("Basic ") + base64_user_pass.len - 1;
    header.data = ngx_pnalloc(r->pool, header.len);
    if(header.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_form_auth: Unable to set remote_user variable; header unset.");
        return;
    }
    ngx_snprintf(header.data, header.len, "Basic %V", &base64_user_pass);

    if(r->headers_in.authorization == NULL) {
        r->headers_in.authorization =
            ngx_pnalloc(r->pool, sizeof(ngx_table_elt_t));
        if(r->headers_in.authorization == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_form_auth: Not enough memory.");
            return;
        }

        r->headers_in.authorization->hash = 1;
        r->headers_in.authorization->key.len = sizeof("Basic") - 1;
        r->headers_in.authorization->key.data = (u_char *)"Basic";
    }
    r->headers_in.authorization->value.len = header.len;
    r->headers_in.authorization->value.data = header.data;
}

static ngx_int_t ngx_http_form_auth_handler(ngx_http_request_t *r)
{
    ngx_http_form_auth_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_form_auth_module);
    if(ctx) {
        if(ctx->done) {
            return NGX_DECLINED;
        }
        return NGX_DONE;
    }

    ngx_http_form_auth_loc_conf_t *loc_conf =
        ngx_http_get_module_loc_conf(r, ngx_http_form_auth_module);
    if(!loc_conf->enabled) {
        return NGX_DECLINED;
    }

    if(r->method != NGX_HTTP_POST) {
        return NGX_DECLINED;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "ngx_form_auth: PAM service name set to %s",
        loc_conf->pam_service.data);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "ngx_form_auth: Login field set to %s",
        loc_conf->login_field.data);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "ngx_form_auth: Passowrd field set to %s",
        loc_conf->password_field.data);
    if(!loc_conf->set_remote_user) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_form_auth: Remote user variable setting is disabled");
    } else {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_form_auth: Remote user variable setting is enabled");
    }

    int steps = 0;
    ngx_int_t rc = 0;

    if(r->headers_in.user.len) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_form_auth: User %s already logged in",
            r->headers_in.user.data);
        steps = PAM_STEP_ACCOUNT;
    }

    if(!steps) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_form_auth_ctx_t));
        if(ctx == NULL) {
            return NGX_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_form_auth_module);
    
        rc = ngx_http_read_client_request_body(r, post_handler);
        if(rc == NGX_AGAIN) {
            ctx->wait_for_more_body = 1;
            return NGX_DONE;
        }
        
        ngx_str_t user_login_name;
        ngx_str_t user_password;
        ngx_str_set(&user_login_name, "");
        ngx_str_set(&user_password, "");

        rc = get_credentials(r, &user_login_name, &user_password,
            &loc_conf->login_field, &loc_conf->password_field);   
        if(rc != NGX_OK) {
            return NGX_HTTP_UNAUTHORIZED;
        }

        ngx_str_set(&r->headers_in.user, user_login_name.data);
        ngx_str_set(&r->headers_in.passwd, user_password.data);

        steps = PAM_STEP_ALL;
    }

    rc = authenticate_and_authorize(r, steps, loc_conf,
        (const char *)r->headers_in.user.data,
        (const char *)r->headers_in.passwd.data);

    if(rc != NGX_OK) {
        ngx_str_set(&r->headers_in.user, "");
        ngx_str_set(&r->headers_in.passwd, "");
    } else {
        if(loc_conf->set_remote_user) {
            set_remote_user(r);
        }
    }

    return rc;
}

static ngx_int_t ngx_http_form_auth_init(ngx_conf_t *conf)
{
    ngx_http_handler_pt *handler;
    ngx_http_core_main_conf_t *main_conf;

    main_conf = ngx_http_conf_get_module_main_conf(conf, ngx_http_core_module);
    handler =
        ngx_array_push(&main_conf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if(handler == NULL) {
        return NGX_ERROR;
    }
    *handler = ngx_http_form_auth_handler;
    return NGX_OK;
}
