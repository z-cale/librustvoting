// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "ZcashVotingFFI",
    platforms: [
        .iOS(.v16),
        .macOS(.v12),
    ],
    products: [
        .library(
            name: "ZcashVotingFFI",
            targets: ["ZcashVotingFFI"]
        )
    ],
    targets: [
        .binaryTarget(
            name: "zcash_voting_ffiFFI",
            url: "https://github.com/valargroup/librustvoting/releases/download/0.3.0/zcash_voting_ffiFFI.xcframework.zip",
            checksum: "09816ba188cd72225a08839283f9cd7c66ad0b86350172fee90af61e0a935fd0"
        ),
        .target(
            name: "ZcashVotingFFI",
            dependencies: ["zcash_voting_ffiFFI"],
            path: "Sources/ZcashVotingFFI"
        )
    ]
)
