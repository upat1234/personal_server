/*
 * A partial implementation of HTTP/1.0
 *
 * This code is mainly intended as a replacement for the book's 'tiny.c' server
 * It provides a *partial* implementation of HTTP/1.0 which can form a basis for
 * the assignment.
 *
 * @author G. Back for CS 3214 Spring 2018
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <assert.h>
#include <linux/limits.h>
#include <dirent.h>

#include "http.h"
#include "hexdump.h"
#include "socket.h"
#include "bufio.h"
#include "main.h"
#include "jansson.h"

// Need macros here because of the sizeof
#define CRLF "\r\n"
#define CR "\r"
#define STARTS_WITH(field_name, header) \
    (!strncasecmp(field_name, header, sizeof(header) - 1))

/* Parse HTTP request line, setting req_method, req_path, and req_version. */
static bool
http_parse_request(struct http_transaction *ta)
{
    size_t req_offset;
    ssize_t len = bufio_readline(ta->client->bufio, &req_offset);
    if (len < 2)       // error, EOF, or less than 2 characters
        return false;

    char *request = bufio_offset2ptr(ta->client->bufio, req_offset);
    request[len-2] = '\0';  // replace LF with 0 to ensure zero-termination
    char *endptr;
    char *method = strtok_r(request, " ", &endptr);
    if (method == NULL)
        return false;

    if (!strcmp(method, "GET"))
        ta->req_method = HTTP_GET;
    else if (!strcmp(method, "POST"))
        ta->req_method = HTTP_POST;
    else
        ta->req_method = HTTP_UNKNOWN;

    char *req_path = strtok_r(NULL, " ", &endptr);
    if (req_path == NULL)
        return false;

    ta->req_path = bufio_ptr2offset(ta->client->bufio, req_path);

    char *http_version = strtok_r(NULL, CR, &endptr);
    if (http_version == NULL)  // would be HTTP 0.9
        return false;

    // record client's HTTP version in request
    if (!strcmp(http_version, "HTTP/1.1"))
        ta->req_version = HTTP_1_1;
    else if (!strcmp(http_version, "HTTP/1.0"))
        ta->req_version = HTTP_1_0;
    else
        return false;

    return true;
}

/* Process HTTP headers. */
static bool
http_process_headers(struct http_transaction *ta)
{
    for (;;) {
        size_t header_offset;
        ssize_t len = bufio_readline(ta->client->bufio, &header_offset);
        if (len <= 0)
            return false;

        char *header = bufio_offset2ptr(ta->client->bufio, header_offset);
        if (len == 2 && STARTS_WITH(header, CRLF))       // empty CRLF
            return true;

        header[len-2] = '\0';
        /* Each header field consists of a name followed by a 
         * colon (":") and the field value. Field names are 
         * case-insensitive. The field value MAY be preceded by 
         * any amount of LWS, though a single SP is preferred.
         */
        char *endptr;
        char *field_name = strtok_r(header, ":", &endptr);
        if (field_name == NULL)
            return false;

        // skip white space
        char *field_value = endptr;
        while (*field_value == ' ' || *field_value == '\t')
            field_value++;

        // you may print the header like so
        // printf("Header: %s: %s\n", field_name, field_value);
        if (!strcasecmp(field_name, "Content-Length")) {
            ta->req_content_len = atoi(field_value);
        }

        /* Handle other headers here. Both field_value and field_name
         * are zero-terminated strings.
         */
        
        /* Store the values of the token if a Cookie is present */
        if (!strcasecmp(field_name, "Cookie")) {
            // printf("%s\n", field_value);
            ta->cookie = field_value;
        }

        /* Store the values of the minimum and maximum bytes
           if a Range is present. By default, if not value is
           found, the value of max_byte_value and min_byte_value
           is 0 */
        if (!strcasecmp(field_name, "Range")) {
            ta->range = field_value;
            char * value = field_value;
            if (STARTS_WITH(value, "bytes=")) {
                char * token = value + strlen("bytes=");
                char * value = strtok(token, "-");
                if (value != NULL) {
                    ta->min_byte_value = atoi(value);
                    value = strtok(NULL, "-");
                    if (value != NULL) {
                        ta->max_byte_value = atoi(value);
                    }
                }
            }
        }
    }
}

const int MAX_HEADER_LEN = 2048;

/* add a formatted header to the response buffer. */
void 
http_add_header(buffer_t * resp, char* key, char* fmt, ...)
{
    va_list ap;

    buffer_appends(resp, key);
    buffer_appends(resp, ": ");

    va_start(ap, fmt);
    char *error = buffer_ensure_capacity(resp, MAX_HEADER_LEN);
    int len = vsnprintf(error, MAX_HEADER_LEN, fmt, ap);
    resp->len += len > MAX_HEADER_LEN ? MAX_HEADER_LEN - 1 : len;
    va_end(ap);

    buffer_appends(resp, "\r\n");
}

/* add a content-length header. */
static void
add_content_length(buffer_t *res, size_t len)
{
    http_add_header(res, "Content-Length", "%ld", len);
}

/* start the response by writing the first line of the response 
 * to the response buffer.  Used in send_response_header */
static void
start_response(struct http_transaction * ta, buffer_t *res)
{
    buffer_init(res, 80);

    /* Hint: you must change this as you implement HTTP/1.1.
     * Respond with the highest version the client supports
     * as indicated in the version field of the request.
     */
    if (ta->req_version == HTTP_1_1) {
        buffer_appends(res, "HTTP/1.1 ");
    }
    else {
        buffer_appends(res, "HTTP/1.0 ");
    }

    switch (ta->resp_status) {
    case HTTP_OK:
        buffer_appends(res, "200 OK");
        break;
    case HTTP_PARTIAL_CONTENT:
        buffer_appends(res, "206 Partial Content");
        break;
    case HTTP_BAD_REQUEST:
        buffer_appends(res, "400 Bad Request");
        break;
    case HTTP_PERMISSION_DENIED:
        buffer_appends(res, "403 Permission Denied");
        break;
    case HTTP_NOT_FOUND:
        buffer_appends(res, "404 Not Found");
        break;
    case HTTP_METHOD_NOT_ALLOWED:
        buffer_appends(res, "405 Method Not Allowed");
        break;
    case HTTP_REQUEST_TIMEOUT:
        buffer_appends(res, "408 Request Timeout");
        break;
    case HTTP_REQUEST_TOO_LONG:
        buffer_appends(res, "414 Request Too Long");
        break;
    case HTTP_NOT_IMPLEMENTED:
        buffer_appends(res, "501 Not Implemented");
        break;
    case HTTP_SERVICE_UNAVAILABLE:
        buffer_appends(res, "503 Service Unavailable");
        break;
    case HTTP_INTERNAL_ERROR:
        buffer_appends(res, "500 Internal Server Error");
        break;
    default:  /* else */
        buffer_appends(res, "500 This is not a valid status code."
                "Did you forget to set resp_status?");
        break;
    }
    buffer_appends(res, CRLF);
}

/* Send response headers to client in a single system call. */
static bool
send_response_header(struct http_transaction *ta)
{
    buffer_t response;
    start_response(ta, &response);
    buffer_appends(&ta->resp_headers, CRLF);

    buffer_t *response_and_headers[2] = {
        &response, &ta->resp_headers
    };

    int rc = bufio_sendbuffers(ta->client->bufio, response_and_headers, 2);
    buffer_delete(&response);
    return rc != -1;
}

/* Send a full response to client with the content in resp_body. */
static bool
send_response(struct http_transaction *ta)
{
    // add content-length.  All other headers must have already been set.
    add_content_length(&ta->resp_headers, ta->resp_body.len);
    buffer_appends(&ta->resp_headers, CRLF);
    
    buffer_t response;
    start_response(ta, &response);
    
    buffer_t *response_and_headers[3] = {
        &response, &ta->resp_headers, &ta->resp_body
    };
    
    int rc = bufio_sendbuffers(ta->client->bufio, response_and_headers, 3);
    buffer_delete(&response);
    return rc != -1;
}

const int MAX_ERROR_LEN = 2048;

/* Send an error response. */
static bool
send_error(struct http_transaction * ta, enum http_response_status status, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    char *error = buffer_ensure_capacity(&ta->resp_body, MAX_ERROR_LEN);
    int len = vsnprintf(error, MAX_ERROR_LEN, fmt, ap);
    ta->resp_body.len += len > MAX_ERROR_LEN ? MAX_ERROR_LEN - 1 : len;
    va_end(ap);
    ta->resp_status = status;
    http_add_header(&ta->resp_headers, "Content-Type", "text/plain");
    return send_response(ta);
}

/* Send Not Found response. */
static bool
send_not_found(struct http_transaction *ta)
{
    return send_error(ta, HTTP_NOT_FOUND, "File %s not found", 
        bufio_offset2ptr(ta->client->bufio, ta->req_path));
}

/* A start at assigning an appropriate mime type.  Real-world 
 * servers use more extensive lists such as /etc/mime.types
 */
static const char *
guess_mime_type(char *filename)
{
    char *suffix = strrchr(filename, '.');
    if (suffix == NULL)
        return "text/plain";

    if (!strcasecmp(suffix, ".html"))
        return "text/html";

    if (!strcasecmp(suffix, ".gif"))
        return "image/gif";

    if (!strcasecmp(suffix, ".png"))
        return "image/png";

    if (!strcasecmp(suffix, ".jpg"))
        return "image/jpeg";

    if (!strcasecmp(suffix, ".js"))
        return "text/javascript";

    if (!strcasecmp(suffix, ".svg"))
        return "image/svg+xml";

    if (!strcasecmp(suffix, ".css"))
        return "text/css";

    if (!strcasecmp(suffix, ".mp4")) // if the file is an MP4
        return "video/mp4";

    /* hint: you need to add support for (at least) .css, .svg, and .mp4
     * You can grep /etc/mime.types for the correct types */
    return "text/plain";
}

/*
 * From a string, try to obtain the token associated
 * with the cookie and return it. Return NULL
 * if authentication token is not found.
 */
static char * get_token_from_cookie(char * cookie) {
    /* Save the cookie string in a temporary string incase
       strtok_r manipulates the cookie */
    char * temp_cookie = (char *)malloc(strlen(cookie) + 1);
    memcpy(temp_cookie, cookie, strlen(cookie) + 1);
    char * save_value; 
    char * value = strtok_r(temp_cookie, "; ", &save_value);
    while (value != NULL) {
        /* If an authentication token is found, return
           the value of the token */
        if (STARTS_WITH(value, "auth_jwt_token=")) {
            char * token = strstr(value, "auth_jwt_token=");
            token = token + strlen("auth_jwt_token=");
            return token;
        }
        value = strtok_r(NULL, "; ", &save_value);
    }
    /* Free the temporary string and return NULL so that
       no token is found */
    free(temp_cookie);
    return NULL;
}

/*
 * Given the transaction, see if the user is authenticated. 
 * If they are authenticated, return true, else return false.
 */
static bool handle_authentication(struct http_transaction * ta) {
    /* See if a cookie present */
    if (ta->cookie != NULL) {
        char * ta_token = get_token_from_cookie(ta->cookie);

        /* See if the token can be obtained from the cookie */
        if (ta_token != NULL) {
            jwt_t *claims_token;
            char *key = getenv("SECRET");
            if (key != NULL) {
                /* Try to decode the token, and if we can't return false */
                int rc = jwt_decode(&claims_token, ta_token, (unsigned char *)key, strlen(key));
                if (rc) {
                    return false;
                }

                /* Obtain the value of the experiation time */
                long exp_val = jwt_get_grant_int(claims_token, "exp");
                if (exp_val > 0) {
                    time_t now = time(NULL);
                    /* If the token is not expired, return true */
                    if (now < exp_val) {
                        return true;
                    }
                }
            }    
        }    
    }
    return false;
}

/* Handle HTTP transaction for static files. */
static bool
handle_static_asset(struct http_transaction *ta, char *basedir)
{
    char fname[PATH_MAX];

    assert (basedir != NULL || !!!"No base directory. Did you specify -R?");
    char *req_path = bufio_offset2ptr(ta->client->bufio, ta->req_path);
    // The code below is vulnerable to an attack.  Can you see
    // which?  Fix it to avoid indirect object reference (IDOR) attacks.
    snprintf(fname, sizeof fname, "%s%s", basedir, req_path);

    if (html5_fallback) {
        // Checks if requested path is equal to '/' or ''.
        // If so, we try "/index.html"
        if (strcmp(req_path, "/") == 0 || strcmp(req_path, "") == 0) {
            req_path = "/index.html";
        }
        // Checks if requsted path contains two backslashes and does not contain a period.
        // This means that requested path points to a file without a suffix in a directory.
        // We try the file with suffix ".html".
        else if (strchr(req_path, '/') != NULL) {
            if (strchr(strchr(req_path, '/'), '/') != NULL) {
                if (strchr(strchr(strchr(req_path, '/'), '/'), '.') == NULL) {
                    char new_path[PATH_MAX];
                    snprintf(new_path, sizeof new_path, "%s%s", req_path, ".html");
                    req_path = new_path;
                }
            }
        }
        snprintf(fname, sizeof fname, "%s%s", basedir, req_path);

        // Check if new requested path is accessible.
        if (access(fname, R_OK) == -1) {
            if (errno == EACCES)
                return send_error(ta, HTTP_PERMISSION_DENIED, "Permission denied.");
            else {
                // If not, try "/200.html"
                if (access(fname, R_OK) == -1) {
                    req_path = "/200.html";
                    snprintf(fname, sizeof fname, "%s%s", basedir, req_path);
                    if (access(fname, R_OK) == -1) {
                        return send_error(ta, HTTP_NOT_FOUND, "404: Not Found.\n");
                    }
                }
            }
        }
    }

    /* Check to see if the user is trying to access a private 
       directory. If they are, make sure they are authenicated. 
       If they are not authenticated, an error should be sent
       back to the user */
    char *check_path = strstr(req_path, "/private");
    if (check_path != NULL) {
        bool authenticated = handle_authentication(ta);
        if (!authenticated) {
            return send_error(ta, HTTP_NOT_FOUND, "404: Permission Denied.\n");
        }
    }
    

    // Determine file size
    struct stat st;
    int rc = stat(fname, &st);
    /* Remove this line once your code handles this case */
    // assert (!(html5_fallback && rc == 0 && S_ISDIR(st.st_mode)));

    if (rc == -1) {
        return send_error(ta, HTTP_NOT_FOUND, "Could not stat file.");
    }

    int filefd = open(fname, O_RDONLY);
    if (filefd == -1) {
        return send_not_found(ta);
    }

    ta->resp_status = HTTP_OK;
    http_add_header(&ta->resp_headers, "Content-Type", "%s", guess_mime_type(fname));
    http_add_header(&ta->resp_headers, "Accept-Ranges", "bytes");
    
    /* If there is a range within the transaction, 
       add the correct values to the Content-Range header*/
    if (ta->range != NULL) {
        if (ta->max_byte_value != 0) {
            ta->resp_status = HTTP_PARTIAL_CONTENT;
            http_add_header(&ta->resp_headers, "Content-Range", "bytes %li-%li/%li", 
                ta->min_byte_value, ta->max_byte_value, st.st_size);
        }
        else {
            ta->resp_status = HTTP_PARTIAL_CONTENT;
           http_add_header(&ta->resp_headers, "Content-Range", "bytes %li-%li/%li",  
            ta->min_byte_value, st.st_size-1, st.st_size);
        }
    }

    /* Ensure that the Cotent-Length header is corrent*/
    off_t from = ta->min_byte_value, to = ta->max_byte_value;
    if (ta->max_byte_value == 0) {
        to = st.st_size - 1;
    }
    off_t content_length = to + 1 - from;
    add_content_length(&ta->resp_headers, content_length);

    bool success = send_response_header(ta);
    if (!success)
        goto out;

    // sendfile may send fewer bytes than requested, hence the loop
    while (success && from <= to)
        success = bufio_sendfile(ta->client->bufio, filefd, &from, to + 1 - from) > 0;

out:
    close(filefd);
    return success;
}



static bool
handle_api(struct http_transaction *ta)
{
    if (ta->req_method == HTTP_GET) {
        char *req_path = bufio_offset2ptr(ta->client->bufio, ta->req_path);
        /* See if the user sent a GET request with /api/login */
        if (strcmp(req_path, "/api/login") == 0) {
            http_add_header(&ta->resp_headers, "Content-Type", "application/json");
            /* If the user is not authenticated, send a message */
            if (ta->cookie == NULL) {
                ta->resp_status = HTTP_OK;
                buffer_appends(&ta->resp_body, "{}");    
                return send_response(ta);

            }

            /* Try to obtain the token, and if we can't, 
               send a response */
            char * ta_token = get_token_from_cookie(ta->cookie);
            if (ta_token == NULL) {
                ta->resp_status = HTTP_OK;
                buffer_appends(&ta->resp_body, "{}");    
                return send_response(ta);

            }

            /* Unpack the values within token */
            jwt_t *claims_token;
            char *key = getenv("SECRET");
            if (key == NULL) {
                exit (EXIT_FAILURE);
            }
            int rc = jwt_decode(&claims_token, ta_token, (unsigned char *)key, strlen(key));
            if (rc) {
                ta->resp_status = HTTP_OK;
                buffer_appends(&ta->resp_body, "{}");   
                return send_response(ta);
            }

            /* Get the grants from the claims, specifically useful
               for obtaining the expiration time */
            char * claims_str = jwt_get_grants_json(claims_token, NULL);
            json_t * claims = json_loadb(claims_str, strlen(claims_str), JSON_DISABLE_EOF_CHECK, NULL);
            json_int_t exp_val, iat_val;
            const char * sub;
            json_unpack(claims, "{s:I, s:I, s:s}", 
                "exp", &exp_val, "iat", &iat_val, "sub", &sub);

            /* Check to see if the token has expried */
            time_t now = time(NULL);
            if (now >= exp_val) {
                buffer_appends(&ta->resp_body, "{}");
                return send_error(ta, HTTP_PERMISSION_DENIED, "Token expired\n");
            }
            

            /* Return the claims to the client */
            ta->resp_status = HTTP_OK;
            buffer_appends(&ta->resp_body, claims_str);
        } 
        else if (strcmp(req_path, "/api/video")  == 0) {
            /* Open the directory of the request */
            DIR * base_dir = opendir(server_root);
            struct dirent * dir_contents = readdir(base_dir);
            json_t *array = json_array();
            /* Read all the contents of the directory */
            while (dir_contents != NULL) {
                /* Check to see if the current file is an MP4 file */
                char * file_name = dir_contents->d_name;
                if (strstr(file_name, ".mp4") != NULL) {
                    char file_path[PATH_MAX];
                    snprintf(file_path, sizeof file_path, "%s/%s", server_root, file_name);
                    
                    /* Obtain the file size and name of the file. Append
                       this information to the json array that needs to 
                       be returned */
                    struct stat stat_b;
                    stat(file_path, &stat_b); 
                    off_t file_size = stat_b.st_size;
                    if (ta->min_byte_value != 0) {
                        if (ta->max_byte_value != 0) {
                            if (ta->min_byte_value <= file_size && file_size <= ta->max_byte_value) {
                                json_t * json_val = json_pack("{s:I, s:s}", "size", file_size, "name", file_name);
                                json_array_append_new(array, json_val);
                            
                            }
                        }
                        else {
                            if (ta->min_byte_value <= file_size) {
                                json_t * json_val = json_pack("{s:I, s:s}", "size", file_size, "name", file_name);
                                json_array_append_new(array, json_val);
                            
                            }
                        }
                        http_add_header(&ta->resp_headers, "Content-Type", "%ld", ((ta->max_byte_value - ta->min_byte_value)/file_size));
                    }
                    else {
                        json_t * json_val = json_pack("{s:I, s:s}", "size", file_size, "name", file_name);
                        json_array_append_new(array, json_val);
                    }
                }
                dir_contents = readdir(base_dir);
            }
            /* Convert the json array to a string so that 
               it can be returned to the user */
            char * json_string = json_dumps(array, JSON_INDENT(4));
            ta->resp_status = HTTP_OK;
            buffer_appends(&ta->resp_body, json_string);
            http_add_header(&ta->resp_headers, "Content-Type", "application/json");
        } 
        else {
            ta->resp_status = HTTP_NOT_FOUND;
            buffer_appends(&ta->resp_body, "{}");
        }
    }
    else if (ta->req_method == HTTP_POST) {
        char *req_path = bufio_offset2ptr(ta->client->bufio, ta->req_path);
        /* See if the user sent a POST request with /api/login */
        if (strcmp(req_path, "/api/login")  == 0) {
            /* Obtain the body of the request as a string and convert it to a JSON */
            char *req_body = bufio_offset2ptr(ta->client->bufio, ta->req_body);
            json_t * json_body = json_loadb(req_body, ta->req_body, JSON_DISABLE_EOF_CHECK, NULL);
            if (json_body == NULL) {
                perror("error with loading in as json\n");
                return send_error(ta, HTTP_BAD_REQUEST, "error with loading json.\n");
            }

            /* Obtain the username and password within the request */
            char * username;
            char * password;
            int unpack_val = json_unpack(json_body, "{s:s, s:s}", "username", &username, "password", &password);
            if (unpack_val == -1) {
                perror("error with obtaining values within json\n");
                return send_error(ta, HTTP_BAD_REQUEST, "Username and password could not be obtained.\n");
            }

            /* Obtain the username and password associated with the environment/server */
            char * env_username = getenv("USER_NAME");
            char * env_password = getenv("USER_PASS");

            /* Check if the client's username and password matches that of the system */
            if (username == NULL || password == NULL ||
                strcmp(username, env_username) !=  0 || strcmp(password, env_password) != 0)  {
                perror("incorrect username or password\n");
                return send_error(ta, HTTP_PERMISSION_DENIED, "Username and password do not match.\n");
            }

            /* Code received from jwt_demo_hs256.c.
               Convert the signature to a JSON Web Token
               and obtain the claims */
            jwt_t *mytoken;
            jwt_new(&mytoken);
            jwt_add_grant(mytoken, "sub", username);
            time_t now = time(NULL);
            jwt_add_grant_int(mytoken, "iat", now);
            time_t exp_val = now + token_expiration_time;
            jwt_add_grant_int(mytoken, "exp", exp_val); 

            char * claims = jwt_get_grants_json(mytoken, NULL);
            buffer_appends(&ta->resp_body, claims);
            

            char *key = getenv("SECRET");
            if (key == NULL) {
                exit (EXIT_FAILURE);
            }
            jwt_set_alg(mytoken, JWT_ALG_HS256, (unsigned char *)key, strlen(key));

            char * cookie_name = jwt_encode_str(mytoken);
            
            /* Add the corresponding information to the http header
               and response body */
            http_add_header(&ta->resp_headers, "Content-Type", "application/json");
            http_add_header(&ta->resp_headers, "Set-Cookie", 
                "auth_jwt_token=%s; Path=/; Max-Age=%ld; HttpOnly; SameSite=Lax", 
                cookie_name, token_expiration_time);
            ta->resp_status = HTTP_OK;
        } 
        else if (strcmp(req_path, "/api/logout")  == 0) {
            /* If the user is trying to logout, append a Set-Cookie
               header with a Max-Age of 0 and no token */
            http_add_header(&ta->resp_headers, "Content-Type", "application/json");
            http_add_header(&ta->resp_headers, "Set-Cookie", 
                "auth_jwt_token=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax");
            ta->resp_status = HTTP_OK;
            buffer_appends(&ta->resp_body, "{user has been logged out}");
            
        } 
        else {
            ta->resp_status = HTTP_NOT_FOUND;
            buffer_appends(&ta->resp_body, "{}");
        }

    }
    else {
        ta->resp_status = HTTP_METHOD_NOT_ALLOWED;
        buffer_appends(&ta->resp_body, "{}");
    }

    return send_response(ta);
}

/* Set up an http client, associating it with a bufio buffer. */
void 
http_setup_client(struct http_client *self, struct bufio *bufio)
{
    self->bufio = bufio;
}

/* Handle a single HTTP transaction.  Returns true on success. */
bool
http_handle_transaction(struct http_client *self)
{
    struct http_transaction ta;

    /* Continously process the transaction for  
       persistent connection */
    while(1) {
        memset(&ta, 0, sizeof ta);
        ta.client = self;

        if (!http_parse_request(&ta))
            return false;

        if (!http_process_headers(&ta))
            return false;

        if (ta.req_content_len > 0) {
            int rc = bufio_read(self->bufio, ta.req_content_len, &ta.req_body);
            if (rc != ta.req_content_len)
                return false;

            // To see the body, use this:
            // char *body = bufio_offset2ptr(ta.client->bufio, ta.req_body);
            // hexdump(body, ta.req_content_len);
        }

        buffer_init(&ta.resp_headers, 1024);
        http_add_header(&ta.resp_headers, "Server", "CS3214-Personal-Server");

        /* If the request version is HTTP 1.1, add a header for the connection*/
        if(ta.req_version == HTTP_1_1) {
            http_add_header(&ta.resp_headers, "Connection", "keep-alive");
        }
        buffer_init(&ta.resp_body, 0);

        bool rc = false;
        char *req_path = bufio_offset2ptr(ta.client->bufio, ta.req_path);
        if (STARTS_WITH(req_path, "/api")) {
            rc = handle_api(&ta);
        } 
        else if (STARTS_WITH(req_path, "/private")) {
            /* If user is trying to access a private file, see
               if they are authneticated. If they are, serve them
               their request, else send an error */
            bool authenticated = handle_authentication(&ta);
            if (authenticated) {
                rc = handle_static_asset(&ta, server_root);
            }
            else {
                rc = send_error(&ta, HTTP_PERMISSION_DENIED, "couldn't access file\n");
            }
        } else {
            rc = handle_static_asset(&ta, server_root);
        }

        buffer_delete(&ta.resp_headers);
        buffer_delete(&ta.resp_body);

        /* If the version is HTTP 1.0, break out of the 
           loop */
        if (ta.req_version == HTTP_1_0) {
            return rc;
        }
    }
}
