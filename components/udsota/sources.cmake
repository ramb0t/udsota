# udsota's source files and include dirs, as absolute paths: the one list the component, the host build and an
# out-of-tree host build all take. include() it; it only set()s variables, so ESP-IDF's requirements pass can read it.
#
# By directory: UDSOTA_SERVER_SRCS, UDSOTA_UPDATE_SRCS, UDSOTA_BOOTLOOP_SRCS, and UDSOTA_SRCS (all three), with their
# include dirs; UDSOTA_INCLUDE_DIRS (every public one) and UDSOTA_PRIV_INCLUDE_DIRS (empty: kept so a list that names it
# still expands). By unit, for a host test that
# links only part: UDSOTA_SERVICES_SRCS is udsota_init() and every service, no transport; UDSOTA_ZSTREAM_SRCS needs a
# udsota_inflate_t (udsota_tinfl.c) beside it, and UDSOTA_CODED_SRCS the zstream list and a udsota_patch_t
# (udsota_detools.c).
set(_udsota_d ${CMAKE_CURRENT_LIST_DIR})

set(UDSOTA_SERVER_SRCS   ${_udsota_d}/server/udsota_server.c ${_udsota_d}/server/udsota_codec.c
                         ${_udsota_d}/server/udsota_isotp.c ${_udsota_d}/server/udsota_rxwatch.c
                         ${_udsota_d}/server/udsota_keys.c)
set(UDSOTA_UPDATE_SRCS   ${_udsota_d}/update/udsota_update_codec.c ${_udsota_d}/update/udsota_image.c
                         ${_udsota_d}/update/udsota_isink.c ${_udsota_d}/update/udsota_zstream.c
                         ${_udsota_d}/update/udsota_patch.c ${_udsota_d}/update/udsota_coded.c
                         ${_udsota_d}/update/udsota_update.c)
set(UDSOTA_BOOTLOOP_SRCS ${_udsota_d}/bootloop/udsota_bootloop.c)
set(UDSOTA_SRCS          ${UDSOTA_SERVER_SRCS} ${UDSOTA_UPDATE_SRCS} ${UDSOTA_BOOTLOOP_SRCS})

set(UDSOTA_SERVER_INCLUDE_DIRS   ${_udsota_d}/server/include)
set(UDSOTA_UPDATE_INCLUDE_DIRS   ${_udsota_d}/update/include)
set(UDSOTA_BOOTLOOP_INCLUDE_DIRS ${_udsota_d}/bootloop/include)
set(UDSOTA_INCLUDE_DIRS          ${_udsota_d}/include ${UDSOTA_SERVER_INCLUDE_DIRS} ${UDSOTA_UPDATE_INCLUDE_DIRS}
                                 ${UDSOTA_BOOTLOOP_INCLUDE_DIRS})
set(UDSOTA_PRIV_INCLUDE_DIRS     "")

set(UDSOTA_SERVICES_SRCS ${_udsota_d}/server/udsota_server.c ${_udsota_d}/server/udsota_codec.c
                         ${_udsota_d}/update/udsota_update.c ${_udsota_d}/update/udsota_update_codec.c)
set(UDSOTA_CODEC_SRCS    ${_udsota_d}/server/udsota_codec.c ${_udsota_d}/update/udsota_update_codec.c)
set(UDSOTA_RXWATCH_SRCS  ${_udsota_d}/server/udsota_rxwatch.c)
set(UDSOTA_KEYS_SRCS     ${_udsota_d}/server/udsota_keys.c)
set(UDSOTA_IMAGE_SRCS    ${_udsota_d}/update/udsota_image.c)
set(UDSOTA_ZSTREAM_SRCS  ${_udsota_d}/update/udsota_isink.c ${_udsota_d}/update/udsota_zstream.c)
set(UDSOTA_CODED_SRCS    ${_udsota_d}/update/udsota_patch.c ${_udsota_d}/update/udsota_coded.c)

unset(_udsota_d)
