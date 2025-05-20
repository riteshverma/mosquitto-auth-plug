/*
 * Copyright (c) 2013 Jan-Piet Mens <jp@mens.de>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of mosquitto nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
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

#define MAXPARAMSLEN  1024
#define METHOD_GETUSER   1
#define METHOD_SUPERUSER 2
#define METHOD_ACLCHECK  3

struct jwt_backend {
	char *ip;
	int port;
	char *hostheader;
	char *hostname;
	char *getuser_uri;
	char *superuser_uri;
	char *aclcheck_uri;
	char *getuser_envs;
	char *superuser_envs;
	char *aclcheck_envs;
	char *with_tls;

#ifdef HAVE_LIBJWT
	// Renamed from jwt_secret to jwt_secret_key_value for clarity, stores the actual secret or key content.
	// If validation_type is "public_key_file", this will store the content of the public key file.
	char *jwt_secret_key_value; 
	// Renamed from jwt_alg to jwt_expected_alg
	jwt_alg_t jwt_expected_alg;  

	// New configuration fields
	char *jwt_validation_type;          // e.g., "secret", "public_key_file"
	char *jwt_public_key_path;        // Path to the public key file if type is "public_key_file"
	
	char *jwt_username_claim_name;      // Claim name for username (e.g., "sub", "username")
	char *jwt_superuser_claim_name;     // Claim name for superuser boolean flag (e.g., "is_superuser")
	char *jwt_acl_topic_read_claim_key; // Claim name for read ACLs (subscribe) (e.g., "mosq_acl_read")
	char *jwt_acl_topic_write_claim_key;// Claim name for write ACLs (publish) (e.g., "mosq_acl_write")
#endif
};

void *be_jwt_init();
void be_jwt_destroy(void *conf);
int be_jwt_getuser(void *conf, const char *token, const char *password, char **phash, const char *clientid);
int be_jwt_superuser(void *conf, const char *token);
int be_jwt_aclcheck(void *conf, const char *clientid, const char *token, const char *topic, int acc);
#endif /* BE_JWT */
