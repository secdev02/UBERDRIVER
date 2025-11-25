cmake_minimum_required(VERSION 3.15)

project(PolicyEnumerator)

# Find WDK
find_package(WDK REQUIRED)

# Create the driver
wdk_add_driver(PolicyEnumerator
    TYPE "WDM"
    SOURCES PolicyEnumerator.c
)

# Link with kernel libraries
target_link_libraries(PolicyEnumerator
    WDK::NTOSKRNL
)

# Set driver properties
set_target_properties(PolicyEnumerator PROPERTIES
    VS_GLOBAL_DriverType "WDM"
    VS_GLOBAL_Configuration_DriverTargetPlatform "Desktop"
)

