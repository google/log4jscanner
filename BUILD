go_library(
    name = "jar",
    srcs = [
        "jar.go",
        "rewrite.go",
        "walker.go",
        "walker_other.go",
        "walker_unix.go",
    ],
    visibility = [
        "//goobuntu/jar_scanner:__subpackages__",
    ],
)

go_test(
    name = "jar_test",
    size = "small",
    srcs = [
        "google_test.go",
        "jar_test.go",
        "rewrite_test.go",
        "walker_test.go",
    ],
    data = glob(["testdata/**"]),
    library = ":jar",
    deps = [
        "//base/go:runfiles",
        "//third_party/golang/cmp",
    ],
)

go_binary(
    name = "log4jscanner",
    srcs = ["log4jscanner.go"],
    deps = [":jar"],
)
