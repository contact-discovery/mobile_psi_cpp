
list(APPEND test_targets lowmc)
foreach (target IN ITEMS ${test_targets})
  add_executable("${target}_test" "${target}_test.c")
  target_link_libraries("${target}_test" lowmc)
  apply_base_options("${target}_test")
  add_test(NAME ${target} COMMAND "${target}_test")
endforeach (target)
