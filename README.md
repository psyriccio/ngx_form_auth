Nginx module for POST authentication and authorization
======================================================

This module provides authentication and authorization with credentials submitted
via POST request. Inspired by [mod_intercept_form_submit](http://www.adelton.com/apache/mod_intercept_form_submit/) module for Apache,
you can use login form for authenticating users for your application.

Tried with [freeIPA](http://www.freeipa.org/page/Main_Page) and basic Perl FCGI application.


Installation
------------

1. Download [the nginx source](http://www.nginx.org/en/download.html) and extract it
1. Clone this module repository into the directory
1. Make sure you have installed development libraries for PAM (eg `pam-devel`)
1. Follow the [nginx install documentation](http://nginx.org/en/docs/install.html) and add this module. If you have more modules for authentication, add this as the last one

    ./configure --add-module=ngx_form_auth


Configuration
-------------

* `form_auth` on | off: for enabling / disabling the module
* `form_auth_pam_service`: the name of the PAM service that should be used, if omitted, the default value `nginx` is used
* `form_auth_login`: the name of the login field in the request, if omitted, the default value `login` is used
* `form_auth_password`: the name of the password field in the request, if omitted, the default value `password` is used
* `form_auth_remote_user` on | off: for setting the $remote_user variable, if omitted, the default value `off` is used


Note that setting the $remote_user variable is possible only using Basic
authentication, therefore after the user is authorized we set the Authorization
header to set the variable correctly. If your application uses the REMOTE_USER
header, don't forget to pass the header to it.


Example configuration
---------------------

Example configuration for FCGI application binded to `/var/run/nginx.sock`
socket, using default values for login and password fields. The application
uses REMOTE_USER to check whether any user is successfully logged in.

    location ~ \.cgi {
        fastcgi_pass unix:/var/run/nginx.sock;
        include fastcgi_params;

        location ~ \.cgi/login {
            form_auth on;
            form_auth_pam_service "service";
            form_auth_remote_user on;

            fastcgi_param REMOTE_USER $remote_user if_not_empty;
            fastcgi_pass unix:/var/run/nginx.sock;
            include fastcgi_params;
        }
    }


Debugging information and troubleshooting
-----------------------------------------

To enable debugging output, compile with the `--with-debug` option and set the
`error_log` directive in you configuratin to `debug` level.

If you have unexpected issues with authentication, make sure your PAM setup is
correct (you have the configuration file for the used service in your
`/etc/pam.d/` containing correct settings). Example setup for using SSSD for
authentication and authorization is

    auth    required   pam_sss.so
    account required   pam_sss.so

