// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "zsign",
    platforms: [
        .iOS("14.0"),
        .macOS("11.0"),
    ],
    products: [
        .library(
            name: "zsign",
            targets: ["zsign"]
        ),
        .library(
            name: "Zupersign",
            targets: ["Zupersign"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/SuperchargeApp/SuperchargeCore", .upToNextMinor(from: "1.2.0")),
    ],
    targets: [
        .target(
            name: "zsign",
            dependencies: [
                .product(name: "OpenSSL", package: "SuperchargeCore"),
            ],
            cSettings: [
                .define("main", to: "zsign_main"),
                .headerSearchPath("include/common"),
            ]
        ),
        .target(
            name: "Zupersign",
            dependencies: [
                "zsign",
                .product(name: "OpenSSL", package: "SuperchargeCore"),
                .product(name: "SignerSupport", package: "SuperchargeCore")
            ]
        ),
    ]
)
