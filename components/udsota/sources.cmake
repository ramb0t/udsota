# udsota's source files and include dirs, as absolute paths. include() it; it only set()s variables, so ESP-IDF's
# requirements pass can read it. UDSOTA_COMMON_SRCS (codecs, 0x27 key derivation), UDSOTA_UPDATE_SRCS (the updater
# and its coded-download stages), UDSOTA_BOOTLOOP_SRCS, and UDSOTA_SRCS (all three).
set(_udsota_d ${CMAKE_CURRENT_LIST_DIR})

set(UDSOTA_COMMON_SRCS   ${_udsota_d}/common/udsota_codec.c ${_udsota_d}/common/udsota_keys.c)
set(UDSOTA_UPDATE_SRCS   ${_udsota_d}/update/udsota_update_codec.c ${_udsota_d}/update/udsota_image.c
                         ${_udsota_d}/update/udsota_isink.c ${_udsota_d}/update/udsota_zstream.c
                         ${_udsota_d}/update/udsota_patch.c ${_udsota_d}/update/udsota_coded.c
                         ${_udsota_d}/update/udsota_update.c)
set(UDSOTA_BOOTLOOP_SRCS ${_udsota_d}/bootloop/udsota_bootloop.c)
set(UDSOTA_SRCS          ${UDSOTA_COMMON_SRCS} ${UDSOTA_UPDATE_SRCS} ${UDSOTA_BOOTLOOP_SRCS})

set(UDSOTA_INCLUDE_DIRS  ${_udsota_d}/include ${_udsota_d}/common/include ${_udsota_d}/update/include
                         ${_udsota_d}/bootloop/include)

unset(_udsota_d)
