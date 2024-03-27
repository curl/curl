/* SPDX-FileCopyrightText: 2019 Ryan Tandy <ryan@nardis.ca>
 * SPDX-FileCopyrightText: 2023 John Scott <jscott@posteo.net>
 * SPDX-License-Identifier: OLDAP-2.8 */

/* This test will spin up slapd, set a binary attribute, and check that libcurl can read it. */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <locale.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uchar.h>
#include <unistd.h>
#include <curl/curl.h>
#include <ldap.h>
#include <ldap_utf8.h>
#include <ldif.h>
#if __STDC_NO_VLA__
#error VLA support is required
#endif

/* Note that this is different from the ldap_perror() that older LDAP APIs traditionally ship with. */
static void ldap_perror(int p, const char msg[restrict static 1]) {
	const char *const u8details = ldap_err2string(p);
	const int r = ldap_x_utf8s_to_mbs(NULL, u8details, 0, NULL);
	if(r == -1) {
		fputs("Failed to convert LDAP error message string to the locale's multibyte encoding\n", stderr);
		/* The converter function doesn't need to allocate any resources and the strings
		 * we get from OpenLDAP obviously should be valid UTF-8, so this should be impossible. */
		abort();
	}

	assert(r < INT_MAX);
	char mbsdetails[r+1];
	const int c = ldap_x_utf8s_to_mbs(mbsdetails, u8details, sizeof(mbsdetails), NULL);
	if(c == -1) {
		fputs("Failed to convert LDAP error message string to the locale's multibyte encoding\n", stderr);
		abort();
	}
	assert(c == r);
	if(fprintf(stderr, "%s: %s\n", msg, mbsdetails) < 0) {
		perror("Failed to print error message");
		/* If we can't print to standard error, this might be the only error indication we get. */
		abort();
	}
}

int main(void) {
	if(!setlocale(LC_ALL, "")) {
		fputs("Failed to enable default locale\n", stderr);
		exit(EXIT_FAILURE);
	}
	/* Note that OpenLDAP (and often libcurl) handle UTF-8 strings regardless of the locale.
	 * That's why ldap_perror() does the conversion. */

	/* This needs to be run as root. */
	assert(!geteuid());

	if(setenv("DEBIAN_FRONTEND", "noninteractive", true) == -1) {
		perror("Failed to set DEBIAN_FRONTEND environment variable");
		exit(EXIT_FAILURE);
	}
	if(setenv("DEBCONF_DEBUG", "user|developer", true) == -1) {
		perror("Failed to set DEBCONF_DEBUG environment variable");
		exit(EXIT_FAILURE);
	}

	FILE *const debconf = popen("debconf-set-selections --verbose", "w");
	if(!debconf) {
		perror("Failed to open pipe and invoke debconf-set-selections");
		exit(EXIT_FAILURE);
	}

	if(fputs("slapd slapd/password1 password Password\n"
		"slapd slapd/password2 password Password\n"
		"slapd slapd/domain string example.com\n"
		"slapd slapd/organization string example.com\n", debconf) == EOF) {
		perror("Failed to send slapd configuration parameters over pipe");
		if(pclose(debconf) == -1) {
			perror("Failed to close pipe");
		}
		exit(EXIT_FAILURE);
	}

	int w = pclose(debconf);
	if(w == -1) {
		perror("Failed to close pipe");
		exit(EXIT_FAILURE);
	}
	if(!WIFEXITED(w) || WEXITSTATUS(w) != EXIT_SUCCESS) {
		fputs("debconf-set-selections terminated abnormally\n", stderr);
		exit(EXIT_FAILURE);
	}

	w = system("dpkg-reconfigure --frontend=noninteractive --priority=critical slapd && service slapd restart");
	if(w == -1) {
		perror("Failed to reconfigure and restart slapd");
		exit(EXIT_FAILURE);
	}
	if(!WIFEXITED(w) || WEXITSTATUS(w) != EXIT_SUCCESS) {
		fputs("dpkg-reconfigure failed abnormally or we failed to restart slapd\n", stderr);
		exit(EXIT_FAILURE);
	}

	/* Now slapd should be running so we can add an entry */
	int p;
	if((p = ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &(int){0xFFFF}))
	|| (p = ldap_set_option(NULL, LDAP_OPT_PROTOCOL_VERSION, &(int){LDAP_VERSION3}))) {
		ldap_perror(p, "Failed to set libldap option");
		exit(EXIT_FAILURE);
	}
	LDAP *ldp;
	if(p = ldap_initialize(&ldp, u8"ldapi:///")) {
		ldap_perror(p, "Failed to initialize libldap");
		exit(EXIT_FAILURE);
	}
	unsigned int counter = 0;
	while (p = ldap_connect(ldp)) {
		counter++;
		fprintf(stderr, "ldapi:// connection failed, retrying (count=%u)\n", counter);
		if (counter >= 10) {
			ldap_perror(p, "Failed to connect to slapd over UNIX domain socket");
			if (p = ldap_unbind_ext(ldp, NULL, NULL)) {
				ldap_perror(p, "Failed to deinitialize libldap");
			}
			exit(EXIT_FAILURE);
		}
		sleep(1);
	}
	if(p = ldap_sasl_bind_s(ldp, u8"CN=admin,DC=example,DC=com", LDAP_SASL_SIMPLE, &(struct berval){.bv_len = strlen(u8"Password"), .bv_val = u8"Password"}, NULL, NULL, NULL)) {
		ldap_perror(p, "Failed to bind to directory server");
		if(p = ldap_unbind_ext(ldp, NULL, NULL)) {
			ldap_perror(p, "Failed to deinitialize libldap");
		}
		exit(EXIT_FAILURE);
	}

	/* The compound literals are necessary for const-correctness. */
	LDAPMod *makeorg[] = {
		&(LDAPMod) {
			.mod_type = (char[]) {
				u8"ou"
			},
			.mod_values = (char *[]) {
				(char[]) {
					u8"Accounts"
				},
				NULL
			}
		},
		&(LDAPMod) {
			.mod_type = (char[]) {
				u8"objectClass"
			},
			.mod_values = (char *[]) {
				(char[]) {
					u8"top"
				},
				(char[]) {
					u8"organizationalUnit"
				},
				NULL
			}
		},
		&(LDAPMod) {
			.mod_op = LDAP_MOD_BVALUES,
			.mod_type = (char[]) {
				u8"description"
			},
			.mod_bvalues = (struct berval *[]) {
				&(struct berval) {
					/* Do not include the null character. */
					.bv_len = sizeof(U"Hello, world") - sizeof(char32_t),
					.bv_val = (char *)(char32_t[]) {
						U"Hello, world"
					}
				},
				NULL
			}
		},
		NULL
	};

	if(p = ldap_add_ext_s(ldp, u8"OU=Accounts,DC=example,DC=com", makeorg, NULL, NULL)) {
		ldap_perror(p, "Failed to create organizational unit");
		if(p = ldap_unbind_ext(ldp, NULL, NULL)) {
			ldap_perror(p, "Failed to unbind from directory server");
		}
		exit(EXIT_FAILURE);
	}

	if(p = ldap_unbind_ext(ldp, NULL, NULL)) {
		ldap_perror(p, "Failed to unbind from directory server");
		exit(EXIT_FAILURE);
	}

	const char *tmpdir = getenv("TMPDIR");
	if(!tmpdir) {
		tmpdir = "/tmp/";
	}
	if(setenv("AUTOPKGTEST_ARTIFACTS", tmpdir, false) == -1) {
		perror("Failed to set environment variable");
		exit(EXIT_FAILURE);
	}
	const char *const autopkgtest_artifacts = getenv("AUTOPKGTEST_ARTIFACTS");
	assert(autopkgtest_artifacts);
	if(chdir(autopkgtest_artifacts) == -1) {
		fprintf(stderr, "Failed to change directory into %s: %s\n", autopkgtest_artifacts, strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Now here's where libcurl comes in. */
	CURLcode s = curl_global_init(CURL_GLOBAL_DEFAULT);
	if(s) {
		fprintf(stderr, "Failed to initialize libcurl: %s\n", curl_easy_strerror(s));
		exit(EXIT_FAILURE);
	}
	if(atexit(curl_global_cleanup)) {
		fputs("Failed to register exit handler\n", stderr);
		curl_global_cleanup();
		exit(EXIT_FAILURE);
	}

	LDAPURLDesc url_desc = {
		/* This really should be ldapi, but libcurl knows we're using a UNIX domain socket anyway and we don't want to confuse it. */
		.lud_scheme = (char[]){ u8"ldap" },
		.lud_host = (char[]){ u8"localhost" },
		.lud_dn = (char[]){ u8"DC=example,DC=com" },
		.lud_attrs = (char *[]){ (char[]){ u8"description" }, NULL },
		.lud_scope = LDAP_SCOPE_ONELEVEL,
		.lud_filter = (char[]){ u8"(description=*)" }
	};
	char *const u8url = ldap_url_desc2str(&url_desc);
	if(!u8url) {
		fputs("Failed to generate LDAP URL\n", stderr);
		exit(EXIT_FAILURE);
	}

	CURL *const c = curl_easy_init();
	if(!c) {
		fputs("Failed to get libcurl handle\n", stderr);
		ldap_memfree(u8url);
		exit(EXIT_FAILURE);
	}

	FILE *const ldif = fopen("curl.ldif", "w+x");
	if(!ldif) {
		fprintf(stderr, "Failed to create curl.ldif in %s: %s\n", autopkgtest_artifacts, strerror(errno));
		curl_easy_cleanup(c);
		ldap_memfree(u8url);
		exit(EXIT_FAILURE);
	}
	char errbuf[CURL_ERROR_SIZE];
	if((s = curl_easy_setopt(c, CURLOPT_VERBOSE, 1L))
	|| (s = curl_easy_setopt(c, CURLOPT_WRITEDATA, (void *)ldif))
	|| (s = curl_easy_setopt(c, CURLOPT_ERRORBUFFER, errbuf))
	|| (s = curl_easy_setopt(c, CURLOPT_UNIX_SOCKET_PATH, "/run/slapd/ldapi"))
	|| (s = curl_easy_setopt(c, CURLOPT_URL, u8url))) {
		fprintf(stderr, "Failed to set libcurl option: %s\n", curl_easy_strerror(s));
		curl_easy_cleanup(c);
		ldap_memfree(u8url);
		if(fclose(ldif) == EOF) {
			perror("Failed to close file");
		}
		exit(EXIT_FAILURE);
	}
	ldap_memfree(u8url);

	if(s = curl_easy_perform(c)) {
		fprintf(stderr, "Failed to fetch LDAP data with libcurl: %s: %s\n", curl_easy_strerror(s), errbuf);
		curl_easy_cleanup(c);
		if(fclose(ldif) == EOF) {
			perror("Failed to close file");
		}
		exit(EXIT_FAILURE);
	}
	curl_easy_cleanup(c);

	const long ldif_size = ftell(ldif);
	if(ldif_size == -1) {
		perror("Failed to determine position on stream");
		if(fclose(ldif) == EOF) {
			perror("Failed to close file");
		}
		exit(EXIT_FAILURE);
	}
	if(fseek(ldif, 0, SEEK_SET) == -1) {
		perror("Failed to change position on stream");
		if(fclose(ldif) == EOF) {
			perror("Failed to close file");
		}
		exit(EXIT_FAILURE);
	}

	/* Now let's use getdelim() to try reading the entire file.
	 * Since LDIF is a text format, there shouldn't be any NULL bytes in it,
	 * but we're still going to check since that's the purpose of this test. */
	char *u8ldif = NULL;
	ssize_t u8ldifreadlen = getdelim(&u8ldif, &(size_t){0}, '\0', ldif);
	if(u8ldifreadlen == -1) {
		free(u8ldif);
		if(ferror(ldif)) {
			perror("Failed to read from LDIF file");
		} else {
			fputs("Failed to read from LDIF file: empty file\n", stderr);
		}
		if(fclose(ldif) == EOF) {
			perror("Failed to close file");
		}
		exit(EXIT_FAILURE);
	}

	if(fclose(ldif) == EOF) {
		perror("Failed to close file");
		free(u8ldif);
		exit(EXIT_FAILURE);
	}

	if(u8ldifreadlen != ldif_size) {
		fputs("The LDIF from CURL contains null bytes! That's not right.\n", stderr);
		free(u8ldif);
		exit(EXIT_FAILURE);
	}

	/* Finally, let's see if we can read the attribute without loss of information. */
	struct berval attrname, attrvalue;
	char *cookie = u8ldif;
	for(char *line = ldif_getline(&cookie); line; line = ldif_getline(&cookie)) {
		if(!(p = ldif_parse_line2(line, &attrname, &attrvalue, NULL))) {
			if(!strncmp(attrname.bv_val, u8"description", attrname.bv_len)) {
				break;
			}
			ldap_memfree(attrname.bv_val);
			ldap_memfree(attrvalue.bv_val);
		}
	}
	free(u8ldif);
	if(p) {
		ldap_perror(p, "Failed to parse LDIF line");
		exit(EXIT_FAILURE);
	}

	ldap_memfree(attrname.bv_val);
	if(memcmp(attrvalue.bv_val, U"Hello, world", sizeof(U"Hello, world") - sizeof(char32_t))) {
		ldap_memfree(attrvalue.bv_val);
		fputs("Binary attribute comparison failed!\n", stderr);
		exit(EXIT_FAILURE);
	}
	ldap_memfree(attrvalue.bv_val);
	/* success */
}
