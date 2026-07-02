cmake_minimum_required(VERSION 3.15)
project(PacketFilteringFirewall VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# =============================================================================
# Backend source files (ORIGINAL — DO NOT MODIFY)
# =============================================================================
set(BACKEND_SOURCES
    src/enums.cpp
    src/Packet.cpp
    src/Rule.cpp
    src/LinkedList.cpp
    src/BST.cpp
    src/HashMap.cpp
    src/Stack.cpp
    src/Queue.cpp
    src/FileLogger.cpp
    src/MongoLogger.cpp
    src/TrafficMonitor.cpp
    src/RuleEngine.cpp
    src/PacketProcessor.cpp
    src/PacketSimulator.cpp
    src/AdminCLI.cpp
    src/main.cpp
)

# =============================================================================
# Dear ImGui source files (from third_party)
# =============================================================================
set(IMGUI_DIR ${CMAKE_SOURCE_DIR}/third_party/imgui-1.92.8)
set(IMGUI_SOURCES
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_demo.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/backends/imgui_impl_glfw.cpp
    ${IMGUI_DIR}/backends/imgui_impl_opengl3.cpp
)

# =============================================================================
# ImPlot source files (from third_party)
# =============================================================================
set(IMPLOT_DIR ${CMAKE_SOURCE_DIR}/third_party/implot-1.0)
set(IMPLOT_SOURCES
    ${IMPLOT_DIR}/implot.cpp
    ${IMPLOT_DIR}/implot_items.cpp
    ${IMPLOT_DIR}/implot_demo.cpp
)

# =============================================================================
# GUI source files (NEW)
# =============================================================================
set(GUI_SOURCES
    gui/FirewallGUI.cpp
    gui/TerminalPanel.cpp
    gui/panels/DashboardPanel.cpp
    gui/panels/RulesPanel.cpp
    gui/panels/BlacklistPanel.cpp
    gui/panels/TrafficPanel.cpp
    gui/panels/ThreatsPanel.cpp
    gui/panels/LogsPanel.cpp
    gui/panels/SettingsPanel.cpp
    include/ImGuiColors.cpp
)

# =============================================================================
# Executable target
# =============================================================================
add_executable(Firewall
    ${BACKEND_SOURCES}
    ${IMGUI_SOURCES}
    ${IMPLOT_SOURCES}
    ${GUI_SOURCES}
)

# =============================================================================
# Include directories
# =============================================================================
target_include_directories(Firewall PRIVATE
    include
    gui
    gui/panels
    ${IMGUI_DIR}
    ${IMGUI_DIR}/backends
    ${IMPLOT_DIR}
    ${CMAKE_SOURCE_DIR}/third_party/imgui-1.92.8/examples/libs/glfw/include
)

# =============================================================================
# Find and link GLFW3 and OpenGL
# =============================================================================
find_package(OpenGL REQUIRED)

# Try to find system GLFW3 first, fall back to bundled MSVC library
find_package(glfw3 QUIET)
if (glfw3_FOUND)
    message(STATUS "Using system GLFW3 library")
    target_link_libraries(Firewall PRIVATE OpenGL::GL glfw3 ws2_32 iphlpapi)
else()
    message(STATUS "Using bundled GLFW3 library")
    target_include_directories(Firewall PRIVATE
        ${CMAKE_SOURCE_DIR}/third_party/imgui-1.92.8/examples/libs/glfw/include
    )
    target_link_libraries(Firewall PRIVATE
        OpenGL::GL
        ${CMAKE_SOURCE_DIR}/third_party/imgui-1.92.8/examples/libs/glfw/lib-vc2010-64/glfw3.lib
        ws2_32
        iphlpapi
    )
endif()

# =============================================================================
# MongoDB optional integration
# Configure using: cmake -DWITH_MONGODB=ON ..
# =============================================================================
option(WITH_MONGODB "Compile with MongoDB drivers" OFF)
if (WITH_MONGODB)
    find_package(mongocxx CONFIG REQUIRED)
    find_package(bsoncxx CONFIG REQUIRED)
    target_compile_definitions(Firewall PRIVATE USE_MONGODB)
    target_link_libraries(Firewall PRIVATE mongo::mongocxx_shared mongo::bsoncxx_shared)
    message(STATUS "Configuring build with MongoDB driver support.")
else()
    message(STATUS "Configuring build with flat-file persistence (MongoDB driver disabled).")
endif()

# =============================================================================
# Copy fonts and DLLs to build directory after build
# =============================================================================
add_custom_command(TARGET Firewall POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        "${CMAKE_SOURCE_DIR}/fonts"
        "$<TARGET_FILE_DIR:Firewall>/fonts"
    COMMAND ${CMAKE_COMMAND} -E echo "Copied fonts to build directory"
    COMMENT "Copying fonts directory to output..."
)

# =============================================================================
# GUI build flag
# =============================================================================
target_compile_definitions(Firewall PRIVATE HAS_GUI)
message(STATUS "Configuring build with Dear ImGui GUI.")