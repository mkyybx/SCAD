cmake_minimum_required(VERSION 3.25)
project(SCDetector2)

set(CMAKE_CXX_STANDARD 20)

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" AND "${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    # using Clang
    set(CMAKE_CXX_FLAGS_DEBUG "-g -O1 -fsanitize=address")
    set(CMAKE_C_FLAGS_DEBUG "-g -O1 -fsanitize=address")
endif()


find_package(Boost 1.82.0 REQUIRED COMPONENTS serialization PATHS /home/zwang048/Work/boost_1_82_0/stage/lib/cmake/Boost-1.82.0 NO_DEFAULT_PATH)
set(Boost_DEBUG OFF)
set(Boost_USE_MULTITHREADED ON)

set(Z3_DIR /home/zwang048/Work/z3/cmake-build-release)
# set(YICES_DIR /home/zwang048/Work/yices2/build/x86_64-pc-linux-gnu-release/dist/)
find_package(Z3 REQUIRED CONFIG NO_DEFAULT_PATH)

include_directories(. ${Boost_INCLUDE_DIRS} ${Z3_CXX_INCLUDE_DIRS}) # ${YICES_DIR}/include/)
# link_directories(${YICES_DIR}/lib/)
add_executable(SCDetector2 LogReader.cpp main.cpp BasicType.cpp Utils.cpp SyncQ.h Z3Manager.cpp GlobalVariables.cpp WorkerPool.h ProgressPrinter.cpp PathPairChecker.cpp SCDLooper.cpp ResultPrinter.cpp Dijkstra.h LRUCache.h KnownResults.cpp PartialPathGenerator.cpp Using.h SecNodeFinder.cpp SolverManager.cpp Worker.cpp)
target_link_libraries(SCDetector2 ${Boost_LIBRARIES} ${Z3_LIBRARIES} -lpthread)
target_compile_options(SCDetector2 PRIVATE ${Z3_COMPONENT_CXX_FLAGS})

add_compile_definitions(SCD_THREADS=79) # Reserve one for non-computing-heavy tasks
add_compile_definitions(OWNER_ATTACKER=1)
add_compile_definitions(OWNER_VICTIM=2)
add_compile_definitions(NO_MED_TO_MED)
#add_compile_definitions(DEBUGTEST)