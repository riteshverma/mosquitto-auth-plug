# Load our module (and misc) configuration from config.mk
# It also contains MOSQUITTO_SRC
include config.mk

BE_CFLAGS =
BE_LDFLAGS =
BE_LDADD =
BE_DEPS =
OBJS = auth-plug.o base64.o pbkdf2-check.o log.o envs.o hash.o be-psk.o backends.o cache.o

BACKENDS =
BACKENDSTR =

ifneq ($(BACKEND_CDB),no)
	BACKENDS += -DBE_CDB
	BACKENDSTR += CDB

	CDBDIR = contrib/tinycdb-0.78
	CDB = $(CDBDIR)/cdb
	CDBINC = $(CDBDIR)/
	CDBLIB = $(CDBDIR)/libcdb.a
	BE_CFLAGS += -I$(CDBINC)/
	BE_LDFLAGS += -L$(CDBDIR)
	BE_LDADD += -lcdb
	BE_DEPS += $(CDBLIB)
	OBJS += be-cdb.o
endif

ifneq ($(BACKEND_MYSQL),no)
	BACKENDS += -DBE_MYSQL
	BACKENDSTR += MySQL

	BE_CFLAGS += `mysql_config --cflags`
	BE_LDADD += `mysql_config --libs`
	OBJS += be-mysql.o
endif

ifneq ($(BACKEND_SQLITE),no)
	BACKENDS += -DBE_SQLITE
	BACKENDSTR += SQLite

	BE_LDADD += -lsqlite3
	OBJS += be-sqlite.o
endif

ifneq ($(BACKEND_REDIS),no)
	BACKENDS += -DBE_REDIS
	BACKENDSTR += Redis

	BE_CFLAGS += -I/usr/local/include/hiredis
	BE_LDFLAGS += -L/usr/local/lib
	BE_LDADD += -lhiredis
	OBJS += be-redis.o
endif

ifeq ($(BACKEND_MEMCACHED),yes)
	BACKENDS += -DBE_MEMCACHED
	BACKENDSTR += Memcached

	BE_CFLAGS += -I/usr/local/include/libmemcached
	BE_LDFLAGS += -L/usr/local/lib
	BE_LDADD += -lmemcached
	OBJS += be-memcached.o
endif

ifneq ($(BACKEND_POSTGRES),no)
	BACKENDS += -DBE_POSTGRES
	BACKENDSTR += PostgreSQL

	BE_CFLAGS += -I`pg_config --includedir`
	BE_LDADD += -L`pg_config --libdir` -lpq
	OBJS += be-postgres.o
endif

ifneq ($(BACKEND_LDAP),no)
	BACKENDS += -DBE_LDAP
	BACKENDSTR += LDAP

	BE_LDADD += -lldap -llber
	OBJS += be-ldap.o
endif

ifneq ($(BACKEND_HTTP), no)
	BACKENDS+= -DBE_HTTP
	BACKENDSTR += HTTP

	BE_LDADD += -lcurl
	OBJS += be-http.o
endif

ifneq ($(BACKEND_JWT), no)
	BACKENDS+= -DBE_JWT
	BACKENDSTR += JWT

	# Conditional libraries for JWT backend
	ifeq ($(HAVE_LIBJWT),yes)
		BE_LDADD += -ljwt -ljansson -lcrypto
		# Add relevant CFLAGS for libjwt if needed, e.g., -I/path/to/libjwt/include
		# BE_CFLAGS += -I/opt/local/include # Example for MacPorts
	else
		BE_LDADD += -lcurl
		# Add relevant CFLAGS for curl if needed
	endif
	OBJS += be-jwt.o
endif

ifneq ($(BACKEND_MONGO), no)
	BACKENDS+= -DBE_MONGO
	BACKENDSTR += MongoDB

	BE_CFLAGS += -I/usr/local/include/
	BE_CFLAGS +=`pkg-config --cflags-only-I libmongoc-1.0 libbson-1.0`
	BE_LDFLAGS +=`pkg-config --libs-only-L libbson-1.0 libmongoc-1.0`
	BE_LDFLAGS += -L/usr/local/lib
	BE_LDADD += -lmongoc-1.0 -lbson-1.0
	OBJS += be-mongo.o
endif

ifneq ($(BACKEND_FILES), no)
	BACKENDS+= -DBE_FILES
	BACKENDSTR += Files

	OBJS += be-files.o
endif

ifeq ($(origin SUPPORT_DJANGO_HASHERS), undefined)
	SUPPORT_DJANGO_HASHERS = no
endif

ifneq ($(SUPPORT_DJANGO_HASHERS), no)
	CFG_CFLAGS += -DSUPPORT_DJANGO_HASHERS
endif

OSSLINC = -I$(OPENSSLDIR)/include
OSSLIBS = -L$(OPENSSLDIR)/lib -lcrypto

CFLAGS := $(CFG_CFLAGS)
CFLAGS += -I$(MOSQUITTO_SRC)/src/
CFLAGS += -I$(MOSQUITTO_SRC)/lib/
ifneq ($(OS),Windows_NT)
	CFLAGS += -fPIC -Wall -Werror
endif
CFLAGS += $(BACKENDS) $(BE_CFLAGS) -I$(MOSQ)/src -DDEBUG=1 $(OSSLINC)

LDFLAGS := $(CFG_LDFLAGS)
LDFLAGS += $(BE_LDFLAGS) -L$(MOSQUITTO_SRC)/lib/
# LDFLAGS += -Wl,-rpath,$(../../../../pubgit/MQTT/mosquitto/lib) -lc
# LDFLAGS += -export-dynamic
LDADD = $(BE_LDADD) $(OSSLIBS) -lmosquitto

all: printconfig auth-plug.so np

printconfig:
	@echo "Selected backends:         $(BACKENDSTR)"
	@echo "Using mosquitto source dir: $(MOSQUITTO_SRC)"
	@echo "OpenSSL install dir:        $(OPENSSLDIR)"
	@echo
	@echo "If you changed the backend selection, you might need to 'make clean' first"
	@echo
	@echo "CFLAGS:  $(CFLAGS)"
	@echo "LDFLAGS: $(LDFLAGS)"
	@echo "LDADD:   $(LDADD)"
	@echo



auth-plug.so : $(OBJS) $(BE_DEPS)
	$(CC) $(CFLAGS) $(LDFLAGS) -fPIC -shared -o $@ $(OBJS) $(BE_DEPS) $(LDADD)

be-redis.o: be-redis.c be-redis.h log.h hash.h envs.h Makefile
be-memcached.o: be-memcached.c be-memcached.h log.h hash.h envs.h Makefile
be-sqlite.o: be-sqlite.c be-sqlite.h Makefile
auth-plug.o: auth-plug.c be-cdb.h be-mysql.h be-sqlite.h Makefile cache.h
be-psk.o: be-psk.c be-psk.h Makefile
be-cdb.o: be-cdb.c be-cdb.h Makefile
be-mysql.o: be-mysql.c be-mysql.h Makefile
be-ldap.o: be-ldap.c be-ldap.h Makefile
be-sqlite.o: be-sqlite.c be-sqlite.h Makefile
pbkdf2-check.o: pbkdf2-check.c base64.h Makefile
base64.o: base64.c base64.h Makefile
log.o: log.c log.h Makefile
envs.o: envs.c envs.h Makefile
hash.o: hash.c hash.h uthash.h Makefile
be-postgres.o: be-postgres.c be-postgres.h Makefile
cache.o: cache.c cache.h uthash.h Makefile
be-http.o: be-http.c be-http.h Makefile backends.h
be-jwt.o: be-jwt.c be-jwt.h Makefile backends.h
be-mongo.o: be-mongo.c be-mongo.h Makefile
be-files.o: be-files.c be-files.h Makefile

np: np.c base64.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(OSSLIBS)

$(CDBLIB):
	(cd $(CDBDIR); make libcdb.a cdb )

pwdb.cdb: pwdb.in
	$(CDB) -c -m  pwdb.cdb pwdb.in
clean :
	rm -f *.o *.so np test_jwt test_jwt.o
	(cd contrib/tinycdb-0.78; make realclean )

# --- Tests ---
# Common objects that might be needed by be-jwt.c or its direct includes, excluding other backends
# log.o is needed as be-jwt.c calls _log()
# envs.o for p_stab, though test setup bypasses it for direct config struct population.
# base64.o and hash.o are included as potential utilities.
COMMON_TEST_OBJS = log.o base64.o hash.o envs.o

# For JWT tests, we must use libjwt, so HAVE_LIBJWT=yes is assumed for this test build.
BE_JWT_LIBS_FOR_TESTING = -ljwt -ljansson -lcrypto

# Specific CFLAGS for compiling test_jwt.c and be-jwt.c for testing.
# Ensures HAVE_LIBJWT is defined, and includes paths to mosquitto sources for mosquitto_plugin.h.
# Uses existing CFLAGS as a base for includes and general flags.
TEST_JWT_CFLAGS = $(CFLAGS) -DHAVE_LIBJWT

# Target to build the test_jwt executable
test_jwt: test_jwt.o be-jwt.o $(COMMON_TEST_OBJS)
	@echo "Linking test_jwt executable..."
	$(CC) $(LDFLAGS) -o $@ $^ $(BE_JWT_LIBS_FOR_TESTING) $(OSSLIBS) $(LDADD) # Add LDADD for -lmosquitto if needed for mosquitto_topic_matches_sub

# Compile test_jwt.c with specific flags
test_jwt.o: test_jwt.c
	$(CC) $(TEST_JWT_CFLAGS) -c -o $@ test_jwt.c

# Rule to recompile be-jwt.o specifically for the test if needed,
# ensuring HAVE_LIBJWT is defined. If the main CFLAGS already do this
# when BACKEND_JWT=yes and HAVE_LIBJWT=yes, this might not be strictly necessary
# but provides explicitness.
# For now, assume the existing be-jwt.o compiled with main CFLAGS is sufficient
# if BACKEND_JWT and HAVE_LIBJWT are set to yes.
# If we need a special version of be-jwt.o for tests:
# be-jwt-test.o: be-jwt.c be-jwt.h
#	$(CC) $(TEST_JWT_CFLAGS) -c -o $@ be-jwt.c
# And then link test_jwt with be-jwt-test.o instead of be-jwt.o

# Target to run the JWT tests
run_jwt_tests: test_jwt
	@echo "Running JWT backend tests..."
	./test_jwt

# General test target
test: run_jwt_tests
# If other test targets exist, add them here:
# test: run_jwt_tests run_other_tests

.PHONY: test run_jwt_tests

config.mk:
	@echo "Please create your own config.mk file"
	@echo "You can use config.mk.in as base"
	@false
