cmake_minimum_required(VERSION 3.16)
project(sovereign_appliance C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

include_directories(include)

# 1. Native Gate Logic Library
add_library(toolgate_core STATIC
    src/toolgate.c
    src/toolexecutor.c
)

# 2. Host Verification Harness Target
add_executable(test_gate verify/harness_toolgate.c)
target_include_directories(test_gate PRIVATE include)
target_compile_options(test_gate PRIVATE -Wall -Wextra -Werror)

# 3. CAmkES Component Source Target (only built when targeting seL4 environment)
if(DEFINED CAMKES)
    DeclareCAmkESComponent(ToolGate
        SOURCES src/toolgate_component.c src/toolgate.c
        INCLUDES include
    )
    DeclareCAmkESComponent(ToolExecutor
        SOURCES src/toolexecutor.c
        INCLUDES include
    )
endif()
