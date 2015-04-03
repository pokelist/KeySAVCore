project("KeySAVCore")

add_library(KeySAVCore
    "${PROJECT_SOURCE_DIR}/src/SaveBreaker.cpp"
    )

include_directories("${PROJECT_SOURCE_DIR}/include")
