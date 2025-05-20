/*
 * Copyright (c) 2013 Jan-Piet Mens <jp@mens.de> wendal
 * <wendal1985()gmai.com> All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer. 2. Redistributions
 * in binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution. 3. Neither the name of mosquitto
 * nor the names of its contributors may be used to endorse or promote
 * products derived from this software without specific prior written
 * permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef BE_JWT
#include "backends.h"
#include "be-jwt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash.h"
#include "log.h"
#include "envs.h"

#ifdef HAVE_LIBJWT
#include <jwt.h>
#include <mosquitto_plugin.h> // For mosquitto_topic_matches_sub
// Potentially include jansson.h if direct access to Jansson objects is needed
// #include <jansson.h>
#else // HAVE_LIBJWT
#include <curl/curl.h>
#endif // HAVE_LIBJWT

#ifndef HAVE_LIBJWT
// This function is only used by the old HTTP-based JWT backend
static int get_string_envs(CURL * curl, const char *required_env, char *querystring)
{
	char *data = NULL;
	char *escaped_key = NULL;
	char *escaped_val = NULL;
	char *env_string = NULL;

	char *params_key[MAXPARAMSNUM];
	char *env_names[MAXPARAMSNUM];
	char *env_value[MAXPARAMSNUM];
	int i, num = 0;

	//_log(LOG_DEBUG, "sys_envs=%s", sys_envs);

	env_string = (char *)malloc(strlen(required_env) + 20);
	if (env_string == NULL) {
		_fatal("ENOMEM");
		return (-1);
	}
	sprintf(env_string, "%s", required_env);

	//_log(LOG_DEBUG, "env_string=%s", env_string);

	num = get_sys_envs(env_string, ",", "=", params_key, env_names, env_value);
	//sprintf(querystring, "");
	for (i = 0; i < num; i++) {
		escaped_key = curl_easy_escape(curl, params_key[i], 0);
		escaped_val = curl_easy_escape(curl, env_value[i], 0);

		//_log(LOG_DEBUG, "key=%s", params_key[i]);
		//_log(LOG_DEBUG, "escaped_key=%s", escaped_key);
		//_log(LOG_DEBUG, "escaped_val=%s", escaped_envvalue);

		data = (char *)malloc(strlen(escaped_key) + strlen(escaped_val) + 1);
		if (data == NULL) {
			_fatal("ENOMEM");
			return (-1);
		}
		sprintf(data, "%s=%s&", escaped_key, escaped_val);
		if (i == 0) {
			sprintf(querystring, "%s", data);
		} else {
			strcat(querystring, data);
		}
	}

	if (data)
		free(data);
	if (escaped_key)
		free(escaped_key);
	if (escaped_val)
		free(escaped_val);
	free(env_string);
	return (num);
}

static int http_post(void *handle, char *uri, const char *clientid, const char *token, const char *topic, int acc, int method)
{
	struct jwt_backend *conf = (struct jwt_backend *)handle;
	CURL *curl;
	struct curl_slist *headerlist = NULL;
	int re;
	int respCode = 0;
	int ok = BACKEND_DEFER;
	char url[BUFSIZ];
	char *data;

	if (token == NULL) {
		return BACKEND_DEFER;
	}
	clientid = (clientid && *clientid) ? clientid : "";
	topic = (topic && *topic) ? topic : "";

	if ((curl = curl_easy_init()) == NULL) {
		_fatal("create curl_easy_handle fails");
		return BACKEND_ERROR;
	}
	if (conf->hostheader != NULL)
		headerlist = curl_slist_append(headerlist, conf->hostheader);
	headerlist = curl_slist_append(headerlist, "Expect:");

	//_log(LOG_NOTICE, "u=%s p=%s t=%s acc=%d", username, password, topic, acc);

	// uri begins with a slash
	snprintf(url, sizeof(url), "%s://%s:%d%s",
		strcmp(conf->with_tls, "true") == 0 ? "https" : "http",
		conf->hostname ? conf->hostname : conf->ip,
		conf->port,
		uri);

	char *escaped_token = curl_easy_escape(curl, token, 0);
	char *escaped_topic = curl_easy_escape(curl, topic, 0);
	char *escaped_clientid = curl_easy_escape(curl, clientid, 0);

	char string_acc[20];
	snprintf(string_acc, 20, "%d", acc);

	char *string_envs = (char *)malloc(MAXPARAMSLEN);
	if (string_envs == NULL) {
		_fatal("ENOMEM");
		return BACKEND_ERROR;
	}
	memset(string_envs, 0, MAXPARAMSLEN);

	//get the sys_env from here
		int env_num = 0;
	if (method == METHOD_GETUSER && conf->getuser_envs != NULL) {
		env_num = get_string_envs(curl, conf->getuser_envs, string_envs);
	} else if (method == METHOD_SUPERUSER && conf->superuser_envs != NULL) {
		env_num = get_string_envs(curl, conf->superuser_envs, string_envs);
	} else if (method == METHOD_ACLCHECK && conf->aclcheck_envs != NULL) {
		env_num = get_string_envs(curl, conf->aclcheck_envs, string_envs);
	}
	if (env_num == -1) {
		return BACKEND_ERROR;
	}
	//----over-- --

		data = (char *)malloc(strlen(string_envs) + strlen(escaped_topic) + strlen(string_acc) + strlen(escaped_clientid) + 30);
	if (data == NULL) {
		_fatal("ENOMEM");
		return BACKEND_ERROR;
	}
	sprintf(data, "%stopic=%s&acc=%s&clientid=%s",
		string_envs,
		escaped_topic,
		string_acc,
		clientid);

	_log(LOG_DEBUG, "url=%s", url);
	_log(LOG_DEBUG, "data=%s", data);
	//curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

	char *token_header = (char *)malloc(strlen(escaped_token) + strlen("Authorization: Bearer ") + 1);
	if (token_header == NULL) {
		_fatal("ENOMEM");
		return BACKEND_ERROR;
	}
	sprintf(token_header, "Authorization: Bearer %s", escaped_token);
	headerlist = curl_slist_append(headerlist, token_header);

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);

	re = curl_easy_perform(curl);
	if (re == CURLE_OK) {
		re = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &respCode);
		if (re == CURLE_OK && respCode >= 200 && respCode < 300) {
			ok = BACKEND_ALLOW;
		} else if (re == CURLE_OK && respCode >= 500) {
			ok = BACKEND_ERROR;
		} else {
			//_log(LOG_NOTICE, "http auth fail re=%d respCode=%d", re, respCode);
		}
	} else {
		_log(LOG_DEBUG, "http req fail url=%s re=%s", url, curl_easy_strerror(re));
		ok = BACKEND_ERROR;
	}

	curl_easy_cleanup(curl);
	curl_slist_free_all(headerlist);
	free(data);
	free(string_envs);
	free(escaped_token);
	free(token_header);
	free(escaped_topic);
	free(escaped_clientid);
	return (ok);
}
#endif // HAVE_LIBJWT

void *be_jwt_init()
{
	struct jwt_backend *conf;
	conf = (struct jwt_backend *)malloc(sizeof(struct jwt_backend));
	if (!conf) {
		_fatal("ENOMEM");
		return NULL;
	}
	memset(conf, 0, sizeof(struct jwt_backend));

#ifdef HAVE_LIBJWT
	// Initialize libjwt specific configurations
	char *alg_str = NULL;

	// Parse jwt_validation_type
	conf->jwt_validation_type = p_stab("jwt_validation_type");
	if (!conf->jwt_validation_type) {
		_log(LOG_INFO, "JWT: 'jwt_validation_type' not configured, defaulting to 'secret'.");
		conf->jwt_validation_type = strdup("secret");
	} else {
		conf->jwt_validation_type = strdup(conf->jwt_validation_type); // Duplicate for safe memory management
	}

	// Parse jwt_secret_key or jwt_public_key_path based on validation_type
	if (strcmp(conf->jwt_validation_type, "secret") == 0) {
		conf->jwt_secret_key_value = p_stab("jwt_secret_key");
		if (!conf->jwt_secret_key_value) {
			_fatal("JWT: 'jwt_secret_key' is required when 'jwt_validation_type' is 'secret'.");
			free(conf->jwt_validation_type);
			free(conf);
			return NULL;
		}
		conf->jwt_secret_key_value = strdup(conf->jwt_secret_key_value);
	} else if (strcmp(conf->jwt_validation_type, "public_key_file") == 0) {
		conf->jwt_public_key_path = p_stab("jwt_public_key_path");
		if (!conf->jwt_public_key_path) {
			_fatal("JWT: 'jwt_public_key_path' is required when 'jwt_validation_type' is 'public_key_file'.");
			free(conf->jwt_validation_type);
			free(conf);
			return NULL;
		}
		conf->jwt_public_key_path = strdup(conf->jwt_public_key_path);
		// Load public key from file
		FILE *fp = fopen(conf->jwt_public_key_path, "r");
		if (!fp) {
			_fatal("JWT: Cannot open public key file: %s", conf->jwt_public_key_path);
			free(conf->jwt_validation_type);
			free(conf->jwt_public_key_path);
			free(conf);
			return NULL;
		}
		fseek(fp, 0, SEEK_END);
		long len = ftell(fp);
		fseek(fp, 0, SEEK_SET);
		conf->jwt_secret_key_value = (char *)malloc(len + 1);
		if (!conf->jwt_secret_key_value) {
			_fatal("JWT: ENOMEM while reading public key file.");
			fclose(fp);
			free(conf->jwt_validation_type);
			free(conf->jwt_public_key_path);
			free(conf);
			return NULL;
		}
		fread(conf->jwt_secret_key_value, 1, len, fp);
		conf->jwt_secret_key_value[len] = '\0';
		fclose(fp);
	} else {
		_fatal("JWT: Invalid 'jwt_validation_type': %s. Must be 'secret' or 'public_key_file'.", conf->jwt_validation_type);
		free(conf->jwt_validation_type);
		free(conf);
		return NULL;
	}

	// Parse jwt_algorithm
	alg_str = p_stab("jwt_algorithm");
	if (!alg_str) {
		_fatal("JWT: 'jwt_algorithm' is missing. Please specify a valid JWT algorithm.");
		// Free previously allocated memory
		if (conf->jwt_validation_type) free(conf->jwt_validation_type);
		if (conf->jwt_secret_key_value) free(conf->jwt_secret_key_value);
		if (conf->jwt_public_key_path) free(conf->jwt_public_key_path);
		free(conf);
		return NULL;
	}
	if (jwt_str_alg(alg_str, &conf->jwt_expected_alg) != 0) {
		_fatal("JWT: Invalid 'jwt_algorithm' specified: %s.", alg_str);
		// Free previously allocated memory
		if (conf->jwt_validation_type) free(conf->jwt_validation_type);
		if (conf->jwt_secret_key_value) free(conf->jwt_secret_key_value);
		if (conf->jwt_public_key_path) free(conf->jwt_public_key_path);
		free(conf);
		return NULL;
	}

	// Parse jwt_username_claim_name
	conf->jwt_username_claim_name = p_stab("jwt_username_claim");
	if (!conf->jwt_username_claim_name) {
		_log(LOG_INFO, "JWT: 'jwt_username_claim' not configured, defaulting to 'sub'.");
		conf->jwt_username_claim_name = strdup("sub");
	} else {
		conf->jwt_username_claim_name = strdup(conf->jwt_username_claim_name);
	}

	// Parse jwt_superuser_claim_name
	conf->jwt_superuser_claim_name = p_stab("jwt_superuser_claim_name");
	if (conf->jwt_superuser_claim_name) {
		conf->jwt_superuser_claim_name = strdup(conf->jwt_superuser_claim_name);
	}

	// Parse jwt_acl_topic_read_claim_key
	conf->jwt_acl_topic_read_claim_key = p_stab("jwt_acl_topic_read_claim_key");
	if (!conf->jwt_acl_topic_read_claim_key) {
		_log(LOG_INFO, "JWT: 'jwt_acl_topic_read_claim_key' not configured, defaulting to 'mosq_acl_read'.");
		conf->jwt_acl_topic_read_claim_key = strdup("mosq_acl_read");
	} else {
		conf->jwt_acl_topic_read_claim_key = strdup(conf->jwt_acl_topic_read_claim_key);
	}

	// Parse jwt_acl_topic_write_claim_key
	conf->jwt_acl_topic_write_claim_key = p_stab("jwt_acl_topic_write_claim_key");
	if (!conf->jwt_acl_topic_write_claim_key) {
		_log(LOG_INFO, "JWT: 'jwt_acl_topic_write_claim_key' not configured, defaulting to 'mosq_acl_write'.");
		conf->jwt_acl_topic_write_claim_key = strdup("mosq_acl_write");
	} else {
		conf->jwt_acl_topic_write_claim_key = strdup(conf->jwt_acl_topic_write_claim_key);
	}
	
	_log(LOG_NOTICE, "JWT backend: Initialized with libjwt support.");
	_log(LOG_INFO, "JWT Config: Validation Type: %s", conf->jwt_validation_type);
	if (strcmp(conf->jwt_validation_type, "public_key_file") == 0) {
		_log(LOG_INFO, "JWT Config: Public Key Path: %s", conf->jwt_public_key_path);
	}
	_log(LOG_INFO, "JWT Config: Algorithm: %s", alg_str ? alg_str : "N/A (Error if NULL)");
	_log(LOG_INFO, "JWT Config: Username Claim: %s", conf->jwt_username_claim_name);
	_log(LOG_INFO, "JWT Config: Superuser Claim: %s", conf->jwt_superuser_claim_name ? conf->jwt_superuser_claim_name : "N/A");
	_log(LOG_INFO, "JWT Config: ACL Read Claim Key: %s", conf->jwt_acl_topic_read_claim_key);
	_log(LOG_INFO, "JWT Config: ACL Write Claim Key: %s", conf->jwt_acl_topic_write_claim_key);

#else // HAVE_LIBJWT
	// Old HTTP-based initialization
	char *ip;
	char *getuser_uri;
	char *superuser_uri;
	char *aclcheck_uri;

	if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
		_fatal("init curl fail");
		free(conf);
		return (NULL);
	}
	if ((ip = p_stab("http_ip")) == NULL) {
		_fatal("Mandatory parameter `http_ip' missing");
		free(conf);
		return (NULL);
	}
	if ((getuser_uri = p_stab("http_getuser_uri")) == NULL) {
		_fatal("Mandatory parameter `http_getuser_uri' missing");
		free(conf);
		return (NULL);
	}
	if ((superuser_uri = p_stab("http_superuser_uri")) == NULL) {
		_fatal("Mandatory parameter `http_superuser_uri' missing");
		free(conf);
		return (NULL);
	}
	if ((aclcheck_uri = p_stab("http_aclcheck_uri")) == NULL) {
		_fatal("Mandatory parameter `http_aclcheck_uri' missing");
		free(conf);
		return (NULL);
	}
	conf->ip = ip;
	conf->hostname = NULL;
	conf->hostheader = NULL;
	conf->port = p_stab("http_port") == NULL ? 80 : atoi(p_stab("http_port"));
	if (p_stab("http_hostname") != NULL) {
		conf->hostheader = (char *)malloc(128);
		conf->hostname = p_stab("http_hostname");
		sprintf(conf->hostheader, "Host: %s", p_stab("http_hostname"));
	}
	conf->getuser_uri = getuser_uri;
	conf->superuser_uri = superuser_uri;
	conf->aclcheck_uri = aclcheck_uri;

	conf->getuser_envs = p_stab("http_getuser_params");
	conf->superuser_envs = p_stab("http_superuser_params");
	conf->aclcheck_envs = p_stab("http_aclcheck_params");

	if (p_stab("http_with_tls") != NULL) {
		conf->with_tls = p_stab("http_with_tls");
	} else {
		conf->with_tls = "false";
	}

	_log(LOG_DEBUG, "with_tls=%s", conf->with_tls);
	_log(LOG_DEBUG, "getuser_uri=%s", getuser_uri);
	_log(LOG_DEBUG, "superuser_uri=%s", superuser_uri);
	_log(LOG_DEBUG, "aclcheck_uri=%s", aclcheck_uri);
	_log(LOG_DEBUG, "getuser_params=%s", conf->getuser_envs);
	_log(LOG_DEBUG, "superuser_params=%s", conf->superuser_envs);
	_log(LOG_DEBUG, "aclcheck_paramsi=%s", conf->aclcheck_envs);
	_log(LOG_NOTICE, "JWT backend: Initialized with HTTP GET support (libjwt not enabled)");

#endif // HAVE_LIBJWT
	return (conf);
};

void be_jwt_destroy(void *handle)
{
	struct jwt_backend *conf = (struct jwt_backend *)handle;

	if (conf) {
#ifdef HAVE_LIBJWT
		// Cleanup libjwt specific resources
		if (conf->jwt_validation_type) free(conf->jwt_validation_type);
		if (conf->jwt_secret_key_value) free(conf->jwt_secret_key_value);
		if (conf->jwt_public_key_path) free(conf->jwt_public_key_path);
		if (conf->jwt_username_claim_name) free(conf->jwt_username_claim_name);
		if (conf->jwt_superuser_claim_name) free(conf->jwt_superuser_claim_name);
		if (conf->jwt_acl_topic_read_claim_key) free(conf->jwt_acl_topic_read_claim_key);
		if (conf->jwt_acl_topic_write_claim_key) free(conf->jwt_acl_topic_write_claim_key);
		_log(LOG_NOTICE, "JWT backend: libjwt resources destroyed");
#else
		if (conf->hostname) free(conf->hostname); 
		if (conf->hostheader) free(conf->hostheader);
		curl_global_cleanup();
		_log(LOG_NOTICE, "JWT backend: HTTP GET destroyed");
#endif
		free(conf);
	}
};

// Parameters:
//  - handle: backend_conf opaque pointer
// Parameters:
//  - handle: backend_conf opaque pointer
//  - username_as_jwt: MQTT username, which is expected to be the JWT string for this function.
//  - password: MQTT password (ignored for authentication, but logged if present).
//  - phash: Pointer to store placeholder hash on success.
//  - clientid: MQTT client ID.
int be_jwt_getuser(void *handle, const char *username_as_jwt, const char *password, char **phash, const char *clientid)
{
#ifdef HAVE_LIBJWT
	struct jwt_backend *conf = (struct jwt_backend *)handle;
	jwt_t *jwt_obj = NULL; 
	int result = BACKEND_DENY; // Default to deny

	_log(LOG_DEBUG, "JWT: be_jwt_getuser called. MQTT Username (expected as JWT): '%s', MQTT Password (ignored): '%s', Client ID: '%s'",
		 username_as_jwt ? username_as_jwt : "NULL", password ? password : "NULL", clientid ? clientid : "NULL");

	if (!username_as_jwt || strlen(username_as_jwt) == 0) {
		_log(LOG_INFO, "JWT: be_jwt_getuser: No JWT provided in MQTT username field. Client ID: '%s'.", clientid ? clientid : "NULL");
		return BACKEND_DENY; 
	}

	if (!conf || !conf->jwt_secret_key_value || !conf->jwt_username_claim_name) {
		_log(LOG_ERR, "JWT: be_jwt_getuser: JWT core configuration (secret/key or username claim name) missing. Client ID: '%s'.", clientid ? clientid : "NULL");
		return BACKEND_ERROR; // Configuration error
	}
	
	size_t key_len = (conf->jwt_expected_alg >= JWT_ALG_HS256 && conf->jwt_expected_alg <= JWT_ALG_HS512) ? strlen(conf->jwt_secret_key_value) : 0;
	int decode_ret = jwt_decode(&jwt_obj, username_as_jwt, (unsigned char *)conf->jwt_secret_key_value, key_len);

	if (decode_ret != 0) {
		const char *err_desc = "unknown error";
		if (decode_ret == EINVAL) err_desc = "invalid parameter to jwt_decode";
		else if (decode_ret == ENOMEM) err_desc = "out of memory";
		else if (decode_ret == ESLOGIC) err_desc = "validation failed (e.g., expired, not yet valid, signature, or audience)";
		_log(LOG_INFO, "JWT: be_jwt_getuser: JWT validation failed for client ID '%s'. Reason: %s (libjwt error code: %d). JWT (from MQTT username): %s",
			 clientid ? clientid : "NULL", err_desc, decode_ret, username_as_jwt);
		if (jwt_obj) jwt_free(jwt_obj);
		return BACKEND_DENY;
	}

    // Validate algorithm after successful decoding
    if (jwt_get_alg(jwt_obj) != conf->jwt_expected_alg) {
        _log(LOG_INFO, "JWT: be_jwt_getuser: JWT algorithm mismatch for MQTT user '%s'. Expected '%s', got '%s'.",
             clientid ? clientid : "NULL", jwt_alg_str(conf->jwt_expected_alg), jwt_alg_str(jwt_get_alg(jwt_obj)));
        if (jwt_obj) jwt_free(jwt_obj);
        return BACKEND_DENY;
    }
	_log(LOG_DEBUG, "JWT: be_jwt_getuser: JWT signature, algorithm, and standard time-related claims (exp, nbf, iat) validated successfully by libjwt for client ID '%s'.", clientid ? clientid : "NULL");

	// Extract username using the configured claim name
	const char *jwt_username_claim = jwt_get_grant(jwt_obj, conf->jwt_username_claim_name);
	if (jwt_username_claim != NULL) {
		// Note: The 'username_as_jwt' is the full JWT. The 'jwt_username_claim' is the actual username extracted from the JWT.
		_log(LOG_INFO, "JWT: be_jwt_getuser: Authentication successful for client ID '%s'. Extracted username ('%s' claim): '%s'. Full JWT (from MQTT username): %s.",
			 clientid ? clientid : "NULL", conf->jwt_username_claim_name, jwt_username_claim, username_as_jwt);
		
		// Set phash to indicate successful JWT validation.
		// auth-plug.c is responsible for freeing this if allocated.
		if (phash) { // Ensure phash pointer is not NULL
			*phash = strdup("jwt_validated");
			if (!*phash) {
				_log(LOG_ERR, "JWT: be_jwt_getuser: strdup failed for phash for client ID '%s'.", clientid ? clientid : "NULL");
				if (jwt_obj) jwt_free(jwt_obj);
				return BACKEND_ERROR; // Memory allocation error
			}
		}
		result = BACKEND_ALLOW;
	} else {
		_log(LOG_INFO, "JWT: be_jwt_getuser: JWT valid, but configured username claim '%s' not found for MQTT user '%s'.",
			 conf->jwt_username_claim_name, clientid ? clientid : "NULL");
		result = BACKEND_DENY;
	}

	if (jwt_obj) jwt_free(jwt_obj);
	return result;
#else
	// Fallback for non-HAVE_LIBJWT (original code using HTTP)
	struct jwt_backend *conf = (struct jwt_backend *)handle;
	int re;
	// Original code used `token` (MQTT username) for HTTP POST, this is kept as is for the old path.
	// If the JWT was intended to be in `pass` for the HTTP path too, that would be a change to the old logic.
	// For consistency with the libjwt path, one might consider using `pass` here too for the JWT.
	// However, the task is to refine the libjwt path.
	// Now, for the old HTTP path, we also need to decide if `username_as_jwt` (MQTT username)
	// or `password` (MQTT password) should be used as the token for the HTTP request.
	// The original code used the `username` parameter of be_jwt_getuser. To maintain that behavior for the non-libjwt path:
	if (username_as_jwt == NULL) { 
		return BACKEND_DEFER;
	}
	re = http_post(handle, conf->getuser_uri, NULL, username_as_jwt, NULL, -1, METHOD_GETUSER);
	return re;
#endif // HAVE_LIBJWT
};

int be_jwt_superuser(void *handle, const char *token)
{
#ifdef HAVE_LIBJWT
// Parameters:
//  - handle: backend_conf opaque pointer
//  - username: MQTT username (this is the 'token' variable from the original function signature, typically the JWT itself for superuser check)
//  - clientid: MQTT client ID (Not directly used by superuser check but available)
int be_jwt_superuser(void *handle, const char *jwt_string_su) // Renamed token to jwt_string_su for clarity
{
#ifdef HAVE_LIBJWT
	struct jwt_backend *conf = (struct jwt_backend *)handle;
	jwt_t *jwt_obj = NULL; // Renamed from jwt to jwt_obj
	int result = BACKEND_DENY; // Default to deny

	_log(LOG_DEBUG, "JWT: be_jwt_superuser called with JWT in username field.");


	if (!jwt_string_su || strlen(jwt_string_su) == 0) {
		_log(LOG_INFO, "JWT: be_jwt_superuser: No JWT provided in username field.");
		return BACKEND_DENY;
	}

	if (!conf || !conf->jwt_secret_key_value) {
		_log(LOG_ERR, "JWT: be_jwt_superuser: JWT secret/key not configured.");
		return BACKEND_ERROR;
	}
    // Check 1: Superuser claim name configuration
    if (!conf->jwt_superuser_claim_name || strlen(conf->jwt_superuser_claim_name) == 0) {
        _log(LOG_INFO, "JWT: be_jwt_superuser: Superuser check deferred. 'jwt_superuser_claim_name' is not configured. JWT: %s", jwt_string_su);
        return BACKEND_DEFER;
    }

	// Check 2: Basic JWT validation (signature, expiry, algorithm)
	size_t key_len = (conf->jwt_expected_alg >= JWT_ALG_HS256 && conf->jwt_expected_alg <= JWT_ALG_HS512) ? strlen(conf->jwt_secret_key_value) : 0;
	int decode_ret = jwt_decode(&jwt_obj, jwt_string_su, (unsigned char *)conf->jwt_secret_key_value, key_len);

	if (decode_ret != 0) {
		const char *err_desc = "unknown error";
        if (decode_ret == EINVAL) err_desc = "invalid parameter to jwt_decode";
        else if (decode_ret == ENOMEM) err_desc = "out of memory";
		else if (decode_ret == ESLOGIC) err_desc = "validation failed (e.g., expired, not yet valid, signature, or audience)";
		_log(LOG_INFO, "JWT: be_jwt_superuser: JWT validation failed. Reason: %s (libjwt error code: %d). Denying access. JWT: %s",
			err_desc, decode_ret, jwt_string_su);
		if (jwt_obj) jwt_free(jwt_obj);
		return BACKEND_DENY;
	}

    if (jwt_get_alg(jwt_obj) != conf->jwt_expected_alg) {
        _log(LOG_INFO, "JWT: be_jwt_superuser: JWT algorithm mismatch. Expected '%s', got '%s'. Denying access. JWT: %s",
             jwt_alg_str(conf->jwt_expected_alg), jwt_alg_str(jwt_get_alg(jwt_obj)), jwt_string_su);
        if (jwt_obj) jwt_free(jwt_obj);
        return BACKEND_DENY;
    }
	_log(LOG_DEBUG, "JWT: be_jwt_superuser: JWT signature, algorithm, and standard time-related claims validated successfully by libjwt. Checking superuser claim '%s'. JWT: %s",
         conf->jwt_superuser_claim_name, jwt_string_su);

	// Check 3: Superuser claim presence and value
	const char *superuser_claim_value_str = jwt_get_grant(jwt_obj, conf->jwt_superuser_claim_name);

	if (superuser_claim_value_str != NULL) {
		// Claim is present, check its boolean value
		// Assuming "true" (case-insensitive) or "1" as true.
		if (strcasecmp(superuser_claim_value_str, "true") == 0 || strcmp(superuser_claim_value_str, "1") == 0) {
			_log(LOG_INFO, "JWT: be_jwt_superuser: Access GRANTED. Superuser claim '%s' is true. JWT: %s",
				 conf->jwt_superuser_claim_name, jwt_string_su);
			result = BACKEND_ALLOW;
		} else {
			_log(LOG_INFO, "JWT: be_jwt_superuser: Superuser check deferred. Superuser claim '%s' is present but not true (value: '%s'). JWT: %s",
				 conf->jwt_superuser_claim_name, superuser_claim_value_str, jwt_string_su);
			result = BACKEND_DEFER;
		}
	} else {
		// Claim is not present
		_log(LOG_INFO, "JWT: be_jwt_superuser: Superuser check deferred. Superuser claim '%s' not found in token. JWT: %s",
			 conf->jwt_superuser_claim_name, jwt_string_su);
		result = BACKEND_DEFER;
	}

	if (jwt_obj) jwt_free(jwt_obj);
	return result;
#else
	// Fallback for non-HAVE_LIBJWT
	struct jwt_backend *conf = (struct jwt_backend *)handle;
	return http_post(handle, conf->superuser_uri, NULL, jwt_string_su, NULL, -1, METHOD_SUPERUSER);
#endif // HAVE_LIBJWT
};

// Parameters:
//  - handle: backend_conf opaque pointer
//  - clientid: MQTT client ID
//  - username: MQTT username (this is the 'token' variable from original signature, typically the JWT for ACL check)
//  - topic: MQTT topic
//  - acc: Access type (MOSQ_ACL_READ, MOSQ_ACL_WRITE)
int be_jwt_aclcheck(void *handle, const char *clientid, const char *jwt_string_acl, const char *topic, int acc) // Renamed token to jwt_string_acl
{
#ifdef HAVE_LIBJWT
	struct jwt_backend *conf = (struct jwt_backend *)handle;
	jwt_t *jwt_obj = NULL; // Renamed from jwt to jwt_obj
	int result = BACKEND_DENY; // Default to deny

	_log(LOG_DEBUG, "JWT: be_jwt_aclcheck called for client ID: '%s', topic: '%s', access: %d, with JWT in username field.",
		 clientid ? clientid : "NULL", topic ? topic : "NULL", acc);


	if (!jwt_string_acl || strlen(jwt_string_acl) == 0) {
		_log(LOG_INFO, "JWT: be_jwt_aclcheck: No JWT provided in username field for client ID '%s'.", clientid ? clientid : "NULL");
		return BACKEND_DENY;
	}

	if (!conf || !conf->jwt_secret_key_value || !conf->jwt_acl_topic_read_claim_key || !conf->jwt_acl_topic_write_claim_key) {
		_log(LOG_ERR, "JWT: be_jwt_aclcheck: JWT core configuration (secret/key or ACL claim keys) missing for client ID '%s'.", clientid ? clientid : "NULL");
		return BACKEND_ERROR;
	}

	size_t key_len = (conf->jwt_expected_alg >= JWT_ALG_HS256 && conf->jwt_expected_alg <= JWT_ALG_HS512) ? strlen(conf->jwt_secret_key_value) : 0;
	int decode_ret = jwt_decode(&jwt_obj, jwt_string_acl, (unsigned char *)conf->jwt_secret_key_value, key_len);

	if (decode_ret != 0) {
		const char *err_desc = (decode_ret == ESLOGIC) ? "validation failed (e.g., expired, not yet valid, signature)" : "decoding error";
		_log(LOG_INFO, "JWT: be_jwt_aclcheck: JWT validation failed for client ID '%s'. Reason: %s (libjwt error code: %d). JWT: %s",
			 clientid ? clientid : "NULL", err_desc, decode_ret, jwt_string_acl);
		if (jwt_obj) jwt_free(jwt_obj);
		return BACKEND_DENY;
	}

    if (jwt_get_alg(jwt_obj) != conf->jwt_expected_alg) {
        _log(LOG_INFO, "JWT: be_jwt_aclcheck: JWT algorithm mismatch for client ID '%s'. Expected '%s', got '%s'.",
             clientid ? clientid : "NULL", jwt_alg_str(conf->jwt_expected_alg), jwt_alg_str(jwt_get_alg(jwt_obj)));
        if (jwt_obj) jwt_free(jwt_obj);
        return BACKEND_DENY;
    }
	_log(LOG_DEBUG, "JWT: be_jwt_aclcheck: JWT signature, algorithm, and standard time-related claims validated successfully by libjwt for client ID '%s'.", clientid ? clientid : "NULL");

    // Step 2: Username and ClientID for Substitutions
    const char *jwt_username = jwt_get_grant(jwt_obj, conf->jwt_username_claim_name);
    if (!jwt_username) {
        _log(LOG_INFO, "JWT: be_jwt_aclcheck: Denying access for client ID '%s'. Username claim '%s' not found in JWT. JWT: %s",
             clientid ? clientid : "NULL", conf->jwt_username_claim_name, jwt_string_acl);
        if (jwt_obj) jwt_free(jwt_obj);
        return BACKEND_DENY;
    }
    _log(LOG_DEBUG, "JWT: be_jwt_aclcheck: Extracted username '%s' from claim '%s' for client ID '%s'.",
         jwt_username, conf->jwt_username_claim_name, clientid ? clientid : "NULL");

	const char *acl_claim_key = NULL;
	if (acc == MOSQ_ACL_READ) { 
		acl_claim_key = conf->jwt_acl_topic_read_claim_key;
		_log(LOG_DEBUG, "JWT: be_jwt_aclcheck: Using READ ACL claim key: '%s' for client ID '%s'.", acl_claim_key ? acl_claim_key : "N/A", clientid ? clientid : "NULL");
	} else if (acc == MOSQ_ACL_WRITE) { 
		acl_claim_key = conf->jwt_acl_topic_write_claim_key;
		_log(LOG_DEBUG, "JWT: be_jwt_aclcheck: Using WRITE ACL claim key: '%s' for client ID '%s'.", acl_claim_key ? acl_claim_key : "N/A", clientid ? clientid : "NULL");
	} else {
		_log(LOG_WARNING, "JWT: be_jwt_aclcheck: Unknown access type %d for client ID '%s'. Deferring.", acc, clientid ? clientid : "NULL");
		if (jwt_obj) jwt_free(jwt_obj);
		return BACKEND_DEFER; // Or DENY, depending on strictness. DEFER seems more appropriate for unknown type.
	}
	
	// Step 3c: Check if the relevant claim key is configured
	if (!acl_claim_key || strlen(acl_claim_key) == 0) {
        _log(LOG_INFO, "JWT: be_jwt_aclcheck: ACL check deferred for client ID '%s'. Relevant ACL claim key for access type %d is not configured. JWT: %s",
             clientid ? clientid : "NULL", acc, jwt_string_acl);
        if (jwt_obj) jwt_free(jwt_obj);
        return BACKEND_DEFER;
    }

	// Step 3d & 3e: Retrieve ACL claim and check type
	json_t *acl_grants_json = jwt_get_grants_json(jwt_obj, acl_claim_key);
	if (!acl_grants_json) {
		_log(LOG_INFO, "JWT: be_jwt_aclcheck: ACL check deferred for client ID '%s'. ACL claim '%s' not found in JWT. JWT: %s",
             clientid ? clientid : "NULL", acl_claim_key, jwt_string_acl);
		if (jwt_obj) jwt_free(jwt_obj);
		return BACKEND_DEFER;
	}

	if (!json_is_array(acl_grants_json)) {
		_log(LOG_WARNING, "JWT: be_jwt_aclcheck: ACL check deferred for client ID '%s'. ACL claim '%s' is not a JSON array. JWT: %s",
             clientid ? clientid : "NULL", acl_claim_key, jwt_string_acl);
		json_decref(acl_grants_json);
		if (jwt_obj) jwt_free(jwt_obj);
		return BACKEND_DEFER;
	}

	// Step 4: Topic Pattern Matching with Substitutions
	size_t index;
	json_t *value;
	char *substituted_pattern = NULL;

	json_array_foreach(acl_grants_json, index, value) {
		if (!json_is_string(value)) {
			_log(LOG_DEBUG, "JWT: be_jwt_aclcheck: Skipping non-string value in ACL array for claim '%s', client ID '%s'.", acl_claim_key, clientid ? clientid : "NULL");
			continue;
		}
		const char *original_pattern = json_string_value(value);
		if (!original_pattern) continue;

		// Perform substitutions: %u -> jwt_username, %c -> clientid
		// Using a simple substitution logic here. A more robust one might be needed for edge cases.
		// This simple version just calculates length and snprintf's. Max length can be an issue.
		// A more robust approach would be iterative replacement or using a library.
		// For now, let's assume a reasonable buffer size or calculate more precisely.
		// Calculate required length for substituted_pattern
		size_t u_count = 0;
		size_t c_count = 0;
		const char *p = original_pattern;
		while (*p) {
			if (strncmp(p, "%u", 2) == 0) u_count++;
			if (strncmp(p, "%c", 2) == 0) c_count++;
			p++;
		}
		
		// Ensure jwt_username and clientid are not NULL before using strlen on them
		size_t username_len = jwt_username ? strlen(jwt_username) : 0;
		size_t clientid_len = clientid ? strlen(clientid) : 0;


		// Max possible length: original_len + u_count * (username_len - 2) + c_count * (clientid_len - 2) + 1
		// Simplified: original_len + u_count * username_len + c_count * clientid_len + 1
		// This estimation is generous to avoid buffer overflows with simple replacement.
		// A more precise calculation would subtract the %u/%c placeholders.
		size_t max_len = strlen(original_pattern) + (u_count * username_len) + (c_count * clientid_len) + 1;
		substituted_pattern = (char *)malloc(max_len);
		if (!substituted_pattern) {
			_log(LOG_ERR, "JWT: be_jwt_aclcheck: Failed to allocate memory for substituted pattern. Client ID: '%s'.", clientid ? clientid : "NULL");
			result = BACKEND_ERROR; // Signal internal error
			goto cleanup_and_return; 
		}

		char *current_sub_ptr = substituted_pattern;
		const char *current_orig_ptr = original_pattern;
		while (*current_orig_ptr) {
			if (strncmp(current_orig_ptr, "%u", 2) == 0 && jwt_username) {
				strcpy(current_sub_ptr, jwt_username);
				current_sub_ptr += username_len;
				current_orig_ptr += 2;
			} else if (strncmp(current_orig_ptr, "%c", 2) == 0 && clientid) {
				strcpy(current_sub_ptr, clientid);
				current_sub_ptr += clientid_len;
				current_orig_ptr += 2;
			} else {
				*current_sub_ptr++ = *current_orig_ptr++;
			}
		}
		*current_sub_ptr = '\0';

		_log(LOG_DEBUG, "JWT: be_jwt_aclcheck: Checking substituted pattern '%s' (original: '%s') against topic '%s' for client ID '%s'.",
			 substituted_pattern, original_pattern, topic, clientid ? clientid : "NULL");

		if (mosquitto_topic_matches_sub(substituted_pattern, topic, NULL) == MOSQ_ERR_SUCCESS) {
			_log(LOG_INFO, "JWT: be_jwt_aclcheck: Access GRANTED for client ID '%s'. Topic '%s' matches substituted pattern '%s' (original: '%s') from ACL claim '%s'. JWT: %s",
				 clientid ? clientid : "NULL", topic, substituted_pattern, original_pattern, acl_claim_key, jwt_string_acl);
			result = BACKEND_ALLOW;
			free(substituted_pattern);
			substituted_pattern = NULL; 
			goto cleanup_and_return; 
		}
		free(substituted_pattern);
		substituted_pattern = NULL;
	}

	// Step 5: No Match / End of Processing
	_log(LOG_INFO, "JWT: be_jwt_aclcheck: Access DEFERRED for client ID '%s'. No matching ACL pattern found in claim '%s' for topic '%s'. JWT: %s",
		 clientid ? clientid : "NULL", acl_claim_key, topic, jwt_string_acl);
	result = BACKEND_DEFER;

cleanup_and_return:
	if (substituted_pattern) free(substituted_pattern); // Should be NULL if loop completed or match found and freed
	if (acl_grants_json) json_decref(acl_grants_json);
	if (jwt_obj) jwt_free(jwt_obj);
	return result;

#else
	// Fallback for non-HAVE_LIBJWT
	struct jwt_backend *conf = (struct jwt_backend *)handle;
	return http_post(conf, conf->aclcheck_uri, clientid, jwt_string_acl, topic, acc, METHOD_ACLCHECK);
#endif // HAVE_LIBJWT
};

#endif /* BE_JWT */
