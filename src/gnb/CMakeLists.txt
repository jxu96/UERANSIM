file(GLOB_RECURSE HDR_FILES *.hpp)
file(GLOB_RECURSE SRC_FILES *.cpp)

add_library(gnb ${HDR_FILES} ${SRC_FILES})

target_compile_options(gnb PRIVATE -Wall -Wextra -pedantic -Wno-unused-parameter -Wno-switch)
# target_compile_options(gnb PRIVATE -Wall -Wextra -pedantic -Wno-unused-parameter -Wno-switch -lrt -lpthread -lboost_system)

target_link_libraries(gnb asn-ngap)
target_link_libraries(gnb asn-rrc)
target_link_libraries(gnb common-lib)
target_link_libraries(gnb ue)
