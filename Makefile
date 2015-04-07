# architecture detection
OS :=           $(shell uname -s | sed 's/ /_/' | tr A-Z a-z)
CPU :=          $(shell uname -m | sed 's/ /_/' | tr A-Z a-z)
ARCH :=         $(OS)_$(CPU)

# check which compiler to use (default clang). e.g. make prefer_gcc=1
ifeq ($(prefer_gcc),1)
CC :=           $(shell which gcc || which clang || which cc)
CXX :=          $(shell which g++ || which clang++ || which c++)
else
CC :=           $(shell which clang || which gcc || which cc)
CXX :=          $(shell which clang++ || which g++ || which c++)
endif

# linker, archiver and ragel parser generator
LD :=           $(CXX)
AR :=           $(shell which ar)
RAGEL :=        $(shell which ragel)

# compiler function tests
check_opt =     $(shell T=$$(mktemp /tmp/test.XXXX.$(2)); echo 'int main() { return 0; }' > $$T ; $(1) $(3) $$T -o /dev/null >/dev/null 2>&1 ; echo $$?; rm $$T)

# compiler flag test definitions
LIBCPP_FLAGS =  -stdlib=libc++
LTO_FLAGS =     -flto
PIE_FLAGS =     -fpie
STPS_FLAGS =    -fstack-protector-strong
STP_FLAGS =     -fstack-protector
RELRO_FLAGS =   -Wl,-z,relro
RELROF_FLAGS =  -Wl,-z,relro,-z,now
NOEXEC_FLAGS =  -Wl,-z,noexecstack

# default optimizer, debug and warning flags
INCLUDES :=     -I$(shell pwd)/src
OPT_FLAGS =     -O3
DEBUG_FLAGS =   -g
WARN_FLAGS =    -Wall -Wpedantic -Wsign-compare
CPPFLAGS =
CXXFLAGS =      -std=c++11 $(OPT_FLAGS) $(DEBUG_FLAGS) $(WARN_FLAGS) $(INCLUDES)
LDFLAGS =       -lpthread -lcrypto -lssl

# check if we can use libc++
ifeq ($(call check_opt,$(CXX),cc,$(LIBCPP_FLAGS)), 0)
CXXFLAGS +=     $(LIBCPP_FLAGS)
endif

# check if hardening is enabled. e.g. make enable_harden=1
ifeq ($(enable_harden),1)
# check if we can use stack protector
ifeq ($(call check_opt,$(CXX),cc,$(STPS_FLAGS)), 0)
CXXFLAGS +=     $(STPS_FLAGS)
else
ifeq ($(call check_opt,$(CXX),cc,$(STP_FLAGS)), 0)
CXXFLAGS +=     $(STP_FLAGS)
endif
endif
# check if we can link with read only relocations
ifeq ($(call check_opt,$(CXX),cc,$(RELROF_FLAGS)), 0)
LDFLAGS +=      $(RELROF_FLAGS)
else
ifeq ($(call check_opt,$(CXX),cc,$(RELRO_FLAGS)), 0)
LDFLAGS +=      $(RELRO_FLAGS)
endif
endif
# check if we can link with non executable stack
ifeq ($(call check_opt,$(CXX),cc,$(NOEXEC_FLAGS)), 0)
LDFLAGS +=      $(NOEXEC_FLAGS)
endif
endif

# check if we can use compile position independent executable
ifeq ($(call check_opt,$(CXX),cc,$(PIE_FLAGS)), 0)
CXXFLAGS +=     $(PIE_FLAGS)
endif

# prefer link time optimization by default with clang
ifeq ($(findstring clang++,$(CXX)),clang++)
enable_lto=1
endif

# check if link time optimization is enabled. e.g. make enable_lto=1
ifeq ($(enable_lto),1)
# check if we can use link time optimization
ifeq ($(call check_opt,$(CXX),cc,$(LTO_FLAGS)), 0)
CXXFLAGS +=     $(LTO_FLAGS)
endif
endif

# check whether to enable sanitizer
ifneq (,$(filter $(sanitize),memory address thread undefined))
CXXFLAGS +=     -fno-omit-frame-pointer -fsanitize=$(sanitize)
ifeq ($(sanitize),memory)
CXXFLAGS +=     -fsanitize-memory-track-origins=2
endif
endif

# architecture specific flags
ifeq ($(OS),linux)
CPPFLAGS +=     -D_FILE_OFFSET_BITS=64
endif

# directories
APP_SRC_DIR =   app
LIB_SRC_DIR =   src
BUILD_DIR =     build
BIN_DIR =       $(BUILD_DIR)/$(ARCH)/bin
LIB_DIR =       $(BUILD_DIR)/$(ARCH)/lib
OBJ_DIR =       $(BUILD_DIR)/$(ARCH)/obj
DEP_DIR =       $(BUILD_DIR)/$(ARCH)/dep

# helper functions
src_objs =      $(subst $(APP_SRC_DIR),$(OBJ_DIR),$(subst $(LIB_SRC_DIR),$(OBJ_DIR),$(subst .cc,.o,$(1))))
src_deps =      $(subst $(APP_SRC_DIR),$(DEP_DIR),$(subst $(LIB_SRC_DIR),$(DEP_DIR),$(subst .cc,.cc.P,$(1))))

# target source and objects
LATYPUS_SRCS =  $(LIB_SRC_DIR)/os.cc \
                $(LIB_SRC_DIR)/io.cc \
                $(LIB_SRC_DIR)/pollset.cc \
                $(LIB_SRC_DIR)/pollset_poll.cc \
                $(LIB_SRC_DIR)/pollset_epoll.cc \
                $(LIB_SRC_DIR)/pollset_kqueue.cc \
                $(LIB_SRC_DIR)/connection.cc \
                $(LIB_SRC_DIR)/resolver.cc \
                $(LIB_SRC_DIR)/netdev.cc \
                $(LIB_SRC_DIR)/socket.cc \
                $(LIB_SRC_DIR)/socket_tcp.cc \
                $(LIB_SRC_DIR)/socket_tls.cc \
                $(LIB_SRC_DIR)/socket_udp.cc \
                $(LIB_SRC_DIR)/socket_unix.cc \
                $(LIB_SRC_DIR)/url.cc \
                $(LIB_SRC_DIR)/cmdline_options.cc \
                $(LIB_SRC_DIR)/config.cc \
                $(LIB_SRC_DIR)/config_parser.cc \
                $(LIB_SRC_DIR)/config_cpu.cc \
                $(LIB_SRC_DIR)/log.cc \
                $(LIB_SRC_DIR)/log_thread.cc \
                $(LIB_SRC_DIR)/http_common.cc \
                $(LIB_SRC_DIR)/http_constants.cc \
                $(LIB_SRC_DIR)/http_date.cc \
                $(LIB_SRC_DIR)/http_parser.cc \
                $(LIB_SRC_DIR)/http_request.cc \
                $(LIB_SRC_DIR)/http_response.cc \
                $(LIB_SRC_DIR)/http_client.cc \
                $(LIB_SRC_DIR)/http_client_handler_file.cc \
                $(LIB_SRC_DIR)/http_server.cc \
                $(LIB_SRC_DIR)/http_server_handler_file.cc \
                $(LIB_SRC_DIR)/http_server_handler_func.cc \
                $(LIB_SRC_DIR)/http_server_handler_stats.cc \
                $(LIB_SRC_DIR)/protocol.cc \
                $(LIB_SRC_DIR)/protocol_engine.cc \
                $(LIB_SRC_DIR)/protocol_thread.cc

LATYPUS_OBJS =  $(call src_objs, $(LATYPUS_SRCS))
LATYPUS_LIB =   $(LIB_DIR)/liblatypus.a

NETA_SRCS =     $(APP_SRC_DIR)/neta.cc
NETA_OBJS =     $(call src_objs, $(NETA_SRCS))
NETA_BIN =      $(BIN_DIR)/neta

NETB_SRCS =     $(APP_SRC_DIR)/netb.cc
NETB_OBJS =     $(call src_objs, $(NETB_SRCS))
NETB_BIN =      $(BIN_DIR)/netb

NETC_SRCS =     $(APP_SRC_DIR)/netc.cc
NETC_OBJS =     $(call src_objs, $(NETC_SRCS))
NETC_BIN =      $(BIN_DIR)/netc

NETD_SRCS =     $(APP_SRC_DIR)/netd.cc
NETD_OBJS =     $(call src_objs, $(NETD_SRCS))
NETD_BIN =      $(BIN_DIR)/netd

ALL_SRCS =      $(LATYPUS_SRCS) $(NETA_SRCS) $(NETB_SRCS) $(NETC_SRCS) $(NETD_SRCS)
BINARIES =      $(NETA_BIN) $(NETB_BIN) $(NETC_BIN) $(NETD_BIN)

# don't build library if LTO is enabled
ifeq ($(enable_lto),1)
LIBS =
else
LIBS =          $(LATYPUS_LIB)
endif

# build rules
all: dirs $(LIBS) $(BINARIES)
.PHONY: dirs
dirs: ; @mkdir -p $(OBJ_DIR) $(LIB_DIR) $(BIN_DIR) $(DEP_DIR)
clean: ; @echo "CLEAN $(BUILD_DIR)"; rm -rf $(BUILD_DIR)

backup: clean ; dir=$$(basename $$(pwd)) ; cd .. && tar -czf $${dir}-backup-$$(date '+%Y%m%d').tar.gz $${dir}
dist: clean ; dir=$$(basename $$(pwd)) ; cd .. && tar --exclude .git -czf $${dir}-$$(date '+%Y%m%d').tar.gz $${dir}

# build targets
ifeq ($(enable_lto),1)
$(NETA_BIN): $(NETA_OBJS) $(LATYPUS_OBJS) ; $(call cmd, LD $@, $(LD) $(CXXFLAGS) $(LDFLAGS) $^ -o $@)
$(NETB_BIN): $(NETB_OBJS) $(LATYPUS_OBJS) ; $(call cmd, LD $@, $(LD) $(CXXFLAGS) $(LDFLAGS) $^ -o $@)
$(NETC_BIN): $(NETC_OBJS) $(LATYPUS_OBJS) ; $(call cmd, LD $@, $(LD) $(CXXFLAGS) $(LDFLAGS) $^ -o $@)
$(NETD_BIN): $(NETD_OBJS) $(LATYPUS_OBJS) ; $(call cmd, LD $@, $(LD) $(CXXFLAGS) $(LDFLAGS) $^ -o $@)
else
$(LATYPUS_LIB): $(LATYPUS_OBJS) ; $(call cmd, AR $@, $(AR) cr $@ $^)
$(NETA_BIN): $(NETA_OBJS) $(LATYPUS_LIB) ; $(call cmd, LD $@, $(LD) $(CXXFLAGS) $(LDFLAGS) $^ -o $@)
$(NETB_BIN): $(NETB_OBJS) $(LATYPUS_LIB) ; $(call cmd, LD $@, $(LD) $(CXXFLAGS) $(LDFLAGS) $^ -o $@)
$(NETC_BIN): $(NETC_OBJS) $(LATYPUS_LIB) ; $(call cmd, LD $@, $(LD) $(CXXFLAGS) $(LDFLAGS) $^ -o $@)
$(NETD_BIN): $(NETD_OBJS) $(LATYPUS_LIB) ; $(call cmd, LD $@, $(LD) $(CXXFLAGS) $(LDFLAGS) $^ -o $@)
endif

# build recipes
ifdef V
cmd = $2
else
cmd = @echo "$1"; $2
endif

$(OBJ_DIR)/%.o : $(APP_SRC_DIR)/%.cc ; $(call cmd, CXX $@, $(CXX) $(CXXFLAGS) $(CPPFLAGS) -c $< -o $@)
$(OBJ_DIR)/%.o : $(LIB_SRC_DIR)/%.cc ; $(call cmd, CXX $@, $(CXX) $(CXXFLAGS) $(CPPFLAGS) -c $< -o $@)
$(LIB_SRC_DIR)/%.cc : $(LIB_SRC_DIR)/%.rl ; $(call cmd, RAGEL $@, $(RAGEL) $< -o $@)
$(DEP_DIR)/%.cc.P : $(APP_SRC_DIR)/%.cc ; @mkdir -p $(DEP_DIR) ;
	$(call cmd, MKDEP $@, $(CXX) $(CXXFLAGS) -MM $< | sed "s#\(.*\)\.o#$(OBJ_DIR)/\1.o $(DEP_DIR)/\1.P#"  > $@)
$(DEP_DIR)/%.cc.P : $(LIB_SRC_DIR)/%.cc ; @mkdir -p $(DEP_DIR) ;
	$(call cmd, MKDEP $@, $(CXX) $(CXXFLAGS) -MM $< | sed "s#\(.*\)\.o#$(OBJ_DIR)/\1.o $(DEP_DIR)/\1.P#"  > $@)

# make dependencies
include $(call src_deps,$(ALL_SRCS))
